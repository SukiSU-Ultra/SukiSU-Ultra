package com.sukisu.ultra.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class AccountUser(
    val id: String = "",
    val username: String = "",
    val displayName: String = "",
    val email: String? = null,
    val avatar: String? = null,
    val role: String = "user",
    val status: String = "pending",
    val emailVerified: Boolean = false,
    val rejectionReason: String? = null,
    val createdAt: String? = null,
    val approvedAt: String? = null,
    val lastLoginAt: String? = null,
)

@Serializable
data class AccountAuthor(
    val hash: String = "",
    val fingerprint: String = "",
    val displayName: String? = null,
    val userId: String? = null,
    val status: String = "pending",
    val autoPublish: Boolean = false,
    val approvedAt: String? = null,
    val lastUsedAt: String? = null,
    val createdAt: String? = null,
    val code: String? = null,
    val nextThemeSeq: Long = 1,
    val avatarPath: String? = null,
)

@Serializable
data class AccountThemeIdResponse(
    val ok: Boolean = false,
    val id: String = "",
    val author: AccountAuthor? = null,
    val error: String? = null,
)

@Serializable
data class AccountThemeSummary(
    val id: String = "",
    val version: Long = 1,
    val name: String = "",
    val author: String = "",
    val description: String = "",
    val tags: List<String> = emptyList(),
    val license: String = "",
    val minManagerVersion: Long = 0,
    val changelog: String = "",
    val sha256: String = "",
    val status: String = "",
    val updatedAt: String? = null,
    val withdrawnAt: String? = null,
    val expiresAt: String? = null,
)

@Serializable
data class AccountThemesResponse(
    val ok: Boolean = false,
    val themes: List<AccountThemeSummary> = emptyList(),
    val error: String? = null,
)

@Serializable
data class AccountSubmission(
    val submissionId: String = "",
    val id: String = "",
    val name: String? = null,
    val version: Long = 1,
    val status: String = "",
    val submittedAt: String? = null,
    val reviewedAt: String? = null,
    val rejectReason: String? = null,
    val autoPublished: Boolean = false,
    val sha256: String = "",
    val previewPath: String? = null,
    val avatarPath: String? = null,
)

@Serializable
data class AccountSubmissionsResponse(
    val ok: Boolean = false,
    val submissions: List<AccountSubmission> = emptyList(),
    val error: String? = null,
)

@Serializable
data class AccountLoginResponse(
    val ok: Boolean = false,
    val user: AccountUser? = null,
    val expiresIn: Long = 0,
    val token: String? = null,
    val error: String? = null,
)

@Serializable
data class AccountProfileResponse(
    val ok: Boolean = false,
    val user: AccountUser? = null,
    val authors: List<AccountAuthor> = emptyList(),
    val activeAuthor: AccountAuthor? = null,
    val github: JsonElement? = null,
    val mailConfigured: Boolean = false,
    val githubConfigured: Boolean = false,
    val error: String? = null,
)

@Serializable
data class AccountSimpleResponse(
    val ok: Boolean = false,
    val message: String? = null,
    val error: String? = null,
    val requiresVerification: Boolean = false,
    val mailSent: Boolean = false,
)

@Serializable
data class AccountSession(
    val baseUrl: String = "",
    val token: String = "",
    val user: AccountUser = AccountUser(),
    val activeAuthor: AccountAuthor? = null,
)

@Serializable
data class AccountRegisterRequest(
    val username: String,
    val displayName: String,
    val email: String,
    val password: String,
)

@Serializable
data class AccountLoginRequest(
    @SerialName("login") val login: String,
    val password: String,
)
