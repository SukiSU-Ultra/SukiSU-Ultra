package com.sukisu.ultra.data.model

import androidx.compose.runtime.Immutable

@Immutable
data class Author(
    val name: String,
    val link: String,
)


@Immutable
data class RepoModule(
    val moduleId: String,
    val moduleName: String,
    val authors: String,
    val authorList: List<Author>,
    val summary: String,
    val tags: List<String>,
    val metamodule: Boolean,
    
    val isScript: Boolean = false,
    val iconUrl: String?,
    val latestVersion: String,
    val latestVersionCode: Int,
    
    val latestReleaseTime: String,
    
    val latestReleaseEpoch: Long,
    
    val stars: Int? = null,
    
    val starsRepository: String? = null,
)

@Immutable
data class RepoModuleList(
    val modules: List<RepoModule>,
    val buildId: String,
    
    val stale: Boolean,
    val error: Throwable?,
)


@Immutable
data class RepoRelease(
    val tag: String,
    val name: String,
    val version: String,
    val versionCode: Int,
    val publishedAt: String,
    val changelogHtml: String?,
    val zipUrl: String,
    val zipName: String,
    val zipSize: Long,
    val sha256: String,
    val tagCommit: String,
    
    val releaseUrl: String,
    
    val attestationUrl: String?,
    val immutable: Boolean,
)

@Immutable
data class RepoModuleDetail(
    val module: RepoModule,
    val license: String?,
    val homepage: String?,
    val support: String?,
    val sourceFullName: String,
    val sourceUrl: String,
    val sourceCommit: String,
    val readmeHtml: String?,
    
    val readmeFailed: Boolean,
    
    val readmeBaseUrl: String,
    val releases: List<RepoRelease>,
    val healthStale: Boolean,
    val webUrl: String,
    val fromCache: Boolean,
)
