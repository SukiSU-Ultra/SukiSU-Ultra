package com.sukisu.ultra.data.model

import androidx.compose.runtime.Immutable

@Immutable
data class Author(
    val name: String,
    val link: String,
)

@Immutable
data class ReleaseAsset(
    val name: String,
    val downloadUrl: String,
    val size: Long
)

@Immutable
data class MmrlVersion(
    val version: String,
    val versionCode: Long,
    val timestamp: Long,
    /** ISO-8601 UTC rendering of [timestamp], empty when unknown. */
    val time: String,
    val zipUrl: String,
    /** Same path on the repository's own host, for indexes whose asset host has moved. */
    val zipUrlFallback: String?,
    val changelogUrl: String?,
    val size: Long,
)

/** Extra data carried by modules from MMRL-format repositories. */
@Immutable
data class MmrlModuleInfo(
    val readmeUrl: String?,
    val supportUrl: String?,
    val versions: List<MmrlVersion>,
)

@Immutable
data class RepoModule(
    val moduleId: String,
    val moduleName: String,
    val authors: String,
    val authorList: List<Author>,
    val summary: String,
    val metamodule: Boolean,
    val zygisk: Boolean = false,
    val stargazerCount: Int,
    val updatedAt: String,
    val createdAt: String,
    val latestRelease: String,
    val latestReleaseTime: String,
    val latestVersionCode: Long,
    val latestAsset: ReleaseAsset?,
    val sourceId: String = "",
    val sourceName: String = "",
    val mmrl: MmrlModuleInfo? = null,
)
