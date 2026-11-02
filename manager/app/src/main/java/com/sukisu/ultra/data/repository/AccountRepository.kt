package com.sukisu.ultra.data.repository

import android.content.Context
import com.sukisu.ultra.data.model.AccountLoginRequest
import com.sukisu.ultra.data.model.AccountLoginResponse
import com.sukisu.ultra.data.model.AccountProfileResponse
import com.sukisu.ultra.data.model.AccountRegisterRequest
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountSubmission
import com.sukisu.ultra.data.model.AccountSubmissionsResponse
import com.sukisu.ultra.data.model.AccountThemeIdResponse
import com.sukisu.ultra.data.model.AccountThemeSummary
import com.sukisu.ultra.data.model.AccountThemesResponse
import com.sukisu.ultra.data.model.AccountSimpleResponse
import com.sukisu.ultra.R
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import androidx.core.content.edit

class AccountRepository(
    context: Context,
    private val client: OkHttpClient = ksuApp.okhttpClient,
) {
    private companion object {
        const val PREFS = "theme_account"
        const val KEY_SESSION = "session"
        const val CSRF_HEADER = "X-Requested-With"
        const val CSRF_VALUE = "SukiSUThemeAdmin"
        const val CLIENT_HEADER = "X-Client"
        val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        val json = Json { ignoreUnknownKeys = true; isLenient = true }
    }

    private val appContext = context.applicationContext
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val _session = MutableStateFlow(loadSession())
    val session: StateFlow<AccountSession?> = _session.asStateFlow()

    private fun loadSession(): AccountSession? {
        val raw = prefs.getString(KEY_SESSION, null) ?: return null
        return runCatching { json.decodeFromString(AccountSession.serializer(), raw) }.getOrNull()
    }

    private fun save(session: AccountSession?) {
        if (session == null) prefs.edit { remove(KEY_SESSION) }
        else prefs.edit {
            putString(
                KEY_SESSION,
                json.encodeToString(AccountSession.serializer(), session)
            )
        }
        _session.value = session
    }

    fun reload() {
        _session.value = loadSession()
    }

    fun sessionFor(baseUrl: String): AccountSession? {
        val normalized = resolvedBase(baseUrl) ?: return null
        val current = _session.value ?: return null
        return current.takeIf { it.baseUrl == normalized && it.token.isNotBlank() }
    }

    fun accountUrl(baseUrl: String): String? =
        resolvedBase(baseUrl)?.let { it + "account/" }

    private fun resolvedBase(baseUrl: String): String? {
        val value = baseUrl.trim().ifBlank { ThemeStoreDefaults.BASE_URL }
        return ThemeStoreRepository.normalizeBaseUrl(value)
    }

    private fun apiBase(baseUrl: String): String? =
        resolvedBase(baseUrl)?.let { it + "account/api/" }

    private fun parseError(raw: String, code: Int): String {
        val specific = runCatching {
            json.parseToJsonElement(raw).jsonObject["error"]?.toString()?.trim('"')
        }.getOrNull()
        return specific?.takeIf { it.isNotBlank() } ?: "HTTP $code"
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
                    if (!parsed.ok || parsed.user == null) throw IOException(parsed.error ?: "Login failed")
                    val token = parsed.token?.takeIf { it.isNotBlank() }
                        ?: throw IOException("Server did not return an account token")
                    val session = AccountSession(
                        baseUrl = resolvedBase(baseUrl) ?: "",
                        token = token,
                        user = parsed.user,
                    )
                    save(session)
                    session
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

    suspend fun refreshProfile(): Result<AccountSession?> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value ?: return@runCatching null
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
                    save(null)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                val parsed = json.decodeFromString(AccountProfileResponse.serializer(), raw)
                val user = parsed.user ?: throw IOException(parsed.error ?: appContext.getString(R.string.account_profile_unavailable))
                val updated = current.copy(user = user, activeAuthor = parsed.activeAuthor)
                save(updated)
                updated
            }
        }
    }


    suspend fun nextThemeId(): Result<AccountThemeIdResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value ?: throw IOException(appContext.getString(R.string.account_login_required))
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
                    save(null)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountThemeIdResponse.serializer(), raw)
            }
        }
    }

    suspend fun myThemes(): Result<List<AccountThemeSummary>> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value ?: throw IOException(appContext.getString(R.string.account_login_required))
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
                    save(null)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountThemesResponse.serializer(), raw).themes
            }
        }
    }

    suspend fun mySubmissions(): Result<List<AccountSubmission>> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value ?: throw IOException(appContext.getString(R.string.account_login_required))
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
                    save(null)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSubmissionsResponse.serializer(), raw).submissions
            }
        }
    }

    suspend fun withdrawTheme(id: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value ?: throw IOException(appContext.getString(R.string.account_login_required))
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
                    save(null)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSimpleResponse.serializer(), raw).message.orEmpty()
            }
        }
    }

    suspend fun restoreTheme(id: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value ?: throw IOException(appContext.getString(R.string.account_login_required))
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
                    save(null)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSimpleResponse.serializer(), raw).message.orEmpty()
            }
        }
    }

    suspend fun logout(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val current = _session.value
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
            }
            save(null)
        }
    }
}
