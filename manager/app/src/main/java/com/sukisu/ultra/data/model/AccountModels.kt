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
data class ThemeComment(
    val id: String = "",
    val themeId: String = "",
    val themeName: String = "",
    val themeAuthor: String = "",
    val userId: String = "",
    val username: String = "",
    val displayName: String = "",
    val parentId: String? = null,
    val visibility: String = "public",
    val content: String = "",
    val createdAt: String = "",
    val avatarUrl: String = "",
    val isThemeAuthor: Boolean = false,
    val isAdmin: Boolean = false,
    val mine: Boolean = false,
    val canDelete: Boolean = false,
    val canReply: Boolean = false,
    val mentionsMe: Boolean = false,
    val replies: List<ThemeComment> = emptyList(),
)

@Serializable
data class ThemeCommentsResponse(
    val ok: Boolean = false,
    val theme: AccountCommentTheme? = null,
    val comments: List<ThemeComment> = emptyList(),
    val isThemeAuthor: Boolean = false,
    val isAdmin: Boolean = false,
    val retentionDays: Long = 0L,
    val error: String? = null,
)

@Serializable
data class AccountCommentTheme(
    val id: String = "",
    val name: String = "",
    val author: String = "",
)

@Serializable
data class ThemeCommentCreateRequest(
    val content: String,
    val visibility: String = "public",
    val parentId: String? = null,
)

@Serializable
data class ThemeCommentCreatedResponse(
    val ok: Boolean = false,
    val comment: ThemeComment? = null,
    val error: String? = null,
)

@Serializable
data class AccountMessageConversation(
    val themeId: String = "",
    val themeName: String = "",
    val themeAuthor: String = "",
    val isThemeAuthor: Boolean = false,
    val mentioned: Boolean = false,
    val lastAt: String = "",
    val comments: List<ThemeComment> = emptyList(),
)

@Serializable
data class AccountUserSummary(
    val username: String = "",
    val displayName: String = "",
    val role: String = "user",
    val isAuthor: Boolean = false,
    val avatarUrl: String = "",
)

@Serializable
data class AccountUserSearchResponse(
    val ok: Boolean = false,
    val users: List<AccountUserSummary> = emptyList(),
    val error: String? = null,
)

@Serializable
data class AccountMessagesResponse(
    val ok: Boolean = false,
    val conversations: List<AccountMessageConversation> = emptyList(),
    val retentionDays: Long = 0L,
    val isAdmin: Boolean = false,
    val error: String? = null,
)

@Serializable
data class AccountCommentChangeResponse(
    val ok: Boolean = false,
    val deleted: Long = 0L,
    val themeId: String = "",
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
    val followers: Long = 0L,
    val following: Long = 0L,
    val passwordConfigured: Boolean = false,
    val mailConfigured: Boolean = false,
    val githubConfigured: Boolean = false,
    val qqConfigured: Boolean = false,
    val error: String? = null,
)

@Serializable
data class AccountFollowedAuthor(
    val authorHash: String = "",
    val displayName: String = "",
)

@Serializable
data class AccountFollowsResponse(
    val ok: Boolean = false,
    val authors: List<AccountFollowedAuthor> = emptyList(),
    val followers: Long = 0L,
    val following: Long = 0L,
    val error: String? = null,
)

@Serializable
data class AccountFollowChangeResponse(
    val ok: Boolean = false,
    val following: Boolean = false,
    val followers: Long = 0L,
    val error: String? = null,
)

@Serializable
data class AccountFollowRequest(
    val authorHash: String,
)

@Serializable
data class AccountForgotPasswordRequest(
    val login: String,
    val email: String = login,
)

@Serializable
data class AccountConfigResponse(
    val ok: Boolean = false,
    val email: Boolean = false,
    val github: Boolean = false,
    val qq: Boolean = false,
    val registration: Boolean = true,
    val accountUrl: String = "",
    val error: String? = null,
)

@Serializable
data class AccountDeviceStartResponse(
    val ok: Boolean = false,
    val deviceCode: String = "",
    val userCode: String = "",
    val verifyUrl: String = "",
    val expiresIn: Long = 0,
    val interval: Long = 2,
    val error: String? = null,
)

@Serializable
data class AccountPreferencesRequest(
    val showR18: Boolean? = null,
    val consentVersion: Long? = null,
)

@Serializable
data class AccountPreferencesResponse(
    val ok: Boolean = false,
    val showR18: Boolean = false,
    /** True when the web account has an explicit R18 preference, not just a consent record. */
    val showR18Set: Boolean = false,
    val consentVersion: Long = 0,
    val consentAt: String? = null,
    val error: String? = null,
)

@Serializable
data class AccountDevicePollResponse(
    val ok: Boolean = false,
    val status: String = "",
    val user: AccountUser? = null,
    val expiresIn: Long = 0,
    val token: String? = null,
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
    val followers: Long = 0L,
    val following: Long = 0L,
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
