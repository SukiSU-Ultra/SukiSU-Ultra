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
    val message: String = "",
    val error: String = "",
)
