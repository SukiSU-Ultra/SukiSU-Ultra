package com.sukisu.ultra.data.model

import kotlinx.serialization.Serializable

/**
 * Catalog served by the theme mirror.
 *
 * The Armbian admin service writes the same shape after each upload or
 * deletion; keep the field names in sync with its catalog builder.
 */
@Serializable
data class ThemeStoreCatalog(
    val schema: Int = 1,
    val formatVersion: Int = 1,
    val minFormatVersion: Int = 1,
    val supportedFormats: List<Int> = emptyList(),
    val generatedAt: String? = null,
    val themes: List<ThemeStoreEntry> = emptyList(),
)

@Serializable
data class ThemeStoreEntry(
    val id: String = "",
    val version: Int = 1,
    val name: String = "",
    val author: String = "",
    val description: String = "",
    val tags: List<String> = emptyList(),
    /** The package carries separate light and dark halves; mirrors may also expose it as a tag. */
    val adaptive: Boolean = false,
    val license: String = "",
    val minManagerVersion: Long = 0L,
    val formatVersion: Int = 1,
    val size: Long = 0L,
    val sha256: String = "",
    val path: String = "",
    val previewPath: String = "",
    val avatarPath: String = "",
    val screenshotPaths: List<String> = emptyList(),
    val updatedAt: String = "",
    val changelog: String = "",
    /** Cumulative package downloads reported by the mirror. */
    val downloads: Long = 0L,
    /** Popularity score: downloads + recent downloads weighted by the mirror. */
    val heat: Long = 0L,
)

/** An additional store source persisted in the manager settings. */
@Serializable
data class ThemeStoreSourceConfig(
    val id: String,
    val name: String = "",
    val baseUrl: String = "",
    val token: String = "",
    val adminUrl: String = "",
)

/** Response returned after a manager upload is queued for review. */
@Serializable
data class ThemeStoreSubmitResponse(
    val ok: Boolean = false,
    val pending: Boolean = false,
    val id: String = "",
    val submissionId: String = "",
    val autoApproved: Boolean = false,
    val sha256: String = "",
    val message: String = "",
    val error: String = "",
)

/** Request body for the mirror's resumable package upload session. */
@Serializable
data class ThemeStoreUploadInitRequest(
    val filename: String,
    val size: Long,
    val fingerprint: String = "",
    /**
     * Preferred chunk size. Older mirrors ignore unknown fields and return their own
     * value; the manager always uploads using the size echoed by the server.
     */
    val chunkSize: Long? = null,
)

/** Response from the mirror's `/health` endpoint. */
@Serializable
data class ThemeStoreHealth(
    val ok: Boolean = false,
    val status: String = "",
    val version: String = "",
    val uptimeSeconds: Long = 0L,
    val checks: ThemeStoreHealthChecks = ThemeStoreHealthChecks(),
)

@Serializable
data class ThemeStoreHealthChecks(
    val database: ThemeStoreHealthCheck = ThemeStoreHealthCheck(),
    val storage: ThemeStoreHealthCheck = ThemeStoreHealthCheck(),
    val catalog: ThemeStoreHealthCheck = ThemeStoreHealthCheck(),
    val pending: ThemeStoreHealthCheck = ThemeStoreHealthCheck(),
)

/** Loose shape shared by the database/storage/catalog/pending health blocks. */
@Serializable
data class ThemeStoreHealthCheck(
    val ok: Boolean = false,
    val latencyMs: Long? = null,
    val themes: Int? = null,
    val count: Int? = null,
    val backend: String = "",
    val generatedAt: String = "",
)

/** Session state returned by `/uploads/init`, `/uploads/{id}` and chunk uploads. */
@Serializable
data class ThemeStoreUploadSession(
    val ok: Boolean = false,
    val uploadId: String = "",
    val filename: String = "",
    val size: Long = 0L,
    val chunkSize: Long = 0L,
    val totalChunks: Long = 0L,
    val received: List<Long> = emptyList(),
    val receivedBytes: Long = 0L,
    val resumed: Boolean = false,
    val error: String? = null,
)
