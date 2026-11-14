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
    /** Site-wide maintenance switch; when true the manager should not present the catalog. */
    val maintenance: Boolean = false,
    val themes: List<ThemeStoreEntry> = emptyList(),
)

@Serializable
data class ThemeStoreEntry(
    val id: String = "",
    val version: Int = 1,
    val name: String = "",
    val author: String = "",
    val authorHash: String = "",
    val description: String = "",
    val tags: List<String> = emptyList(),
    
    val adaptive: Boolean = false,
    val r18: Boolean = false,
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
    
    val downloads: Long = 0L,
    
    val heat: Long = 0L,
)


@Serializable
data class ThemeStoreSourceConfig(
    val id: String,
    val name: String = "",
    val baseUrl: String = "",
    val token: String = "",
    val adminUrl: String = "",
)


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


@Serializable
data class ThemeStoreHealthCheck(
    val ok: Boolean = false,
    val latencyMs: Long? = null,
    val themes: Int? = null,
    val count: Int? = null,
    val backend: String = "",
    val generatedAt: String = "",
)


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
    // null means the legacy server has neither completion nor attachment references.
    val uploadTargets: List<ThemeStoreUploadTarget>? = null,
    val receivedLocal: List<Long> = emptyList(),
    val error: String? = null,
)

@Serializable
data class ThemeStoreUploadTarget(
    val id: String = "",
    val name: String = "",
    val baseUrl: String = "",
    val ticket: String = "",
)

@Serializable
data class ThemeStoreUploadAck(
    val ok: Boolean = false,
    val index: Long? = null,
    val sha256: String = "",
)

@Serializable
data class ThemeStoreUploadComplete(
    val ok: Boolean = false,
    val complete: Boolean = false,
    val missing: List<Long> = emptyList(),
    val error: String? = null,
)
