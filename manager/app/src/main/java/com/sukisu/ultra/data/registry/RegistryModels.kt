package com.sukisu.ultra.data.registry

import kotlinx.serialization.Serializable

/*
 * Client protocol of KernelSU Modules ({baseUrl}/api/v1/...).
 *
 * Mirrors packages/schema/src/api.ts of KernelSU-Modules/tools. Every path inside these
 * documents is relative to the site root (baseUrl). Unknown fields are ignored; an unknown
 * schemaVersion is rejected (see [RegistryParser]).
 */

const val REGISTRY_API_SCHEMA_VERSION = 1


object RegistryKind {
    const val MODULE = "module"
    const val SCRIPT = "script"

    
    fun isKnown(kind: String): Boolean = kind == MODULE || kind == SCRIPT
}

@Serializable
data class ApiIndex(
    val schemaVersion: Int,
    val buildId: String,
    val repoCommit: String,
    val generatedAt: String,
    
    val modules: String,
)

@Serializable
data class ApiVersionRef(
    val version: String,
    val versionCode: Int,
    val publishedAt: String,
)

@Serializable
data class ApiAuthor(
    val name: String,
    val url: String? = null,
)

@Serializable
data class ApiModuleSummary(
    val id: String,
    
    val name: String = "",
    val summary: String = "",
    val authors: List<ApiAuthor> = emptyList(),
    val tags: List<String> = emptyList(),
    val metamodule: Boolean = false,
    
    val kind: String = RegistryKind.MODULE,
    
    val icon: String? = null,
    val stable: ApiVersionRef,
    
    val stars: Int? = null,
    
    val starsRepository: String? = null,
    
    val detail: String,
    val updatedAt: String,
)

@Serializable
data class ApiModules(
    val schemaVersion: Int,
    val buildId: String,
    val modules: List<ApiModuleSummary>,
)

@Serializable
data class ApiZip(
    val url: String,
    val name: String,
    val size: Long,
    val sha256: String,
)

@Serializable
data class ApiRelease(
    val tag: String,
    val name: String? = null,
    val version: String,
    val versionCode: Int,
    val prerelease: Boolean,
    val publishedAt: String,
    
    val changelogHtml: String? = null,
    val zip: ApiZip,
    val tagCommit: String,
    val releaseUrl: String,
    val attestationUrl: String? = null,
    val immutable: Boolean,
)

@Serializable
data class ApiCompatibility(
    val androidMinApi: Int? = null,
    val androidMaxApi: Int? = null,
    val architectures: List<String>? = null,
)

@Serializable
data class ApiSource(
    val host: String,
    val fullName: String,
    val url: String,
    val commit: String,
)

@Serializable
data class ApiHealth(
    val status: String,
    val lastSuccessAt: String? = null,
)

@Serializable
data class ApiModuleDetail(
    val schemaVersion: Int,
    val buildId: String,
    val id: String,
    val name: String = "",
    val summary: String = "",
    val authors: List<ApiAuthor> = emptyList(),
    val tags: List<String> = emptyList(),
    val metamodule: Boolean = false,
    
    val kind: String = RegistryKind.MODULE,
    val icon: String? = null,
    val stable: ApiVersionRef,
    val stars: Int? = null,
    val starsRepository: String? = null,
    val detail: String,
    val updatedAt: String,
    val license: String? = null,
    val homepage: String? = null,
    val support: String? = null,
    val compatibility: ApiCompatibility? = null,
    val source: ApiSource,
    
    val readme: String? = null,
    
    val releases: List<ApiRelease> = emptyList(),
    val health: ApiHealth? = null,
)


data class RegistryCatalog(
    val index: ApiIndex,
    val modules: List<ApiModuleSummary>,
    
    val fromCache: Boolean,
) {
    val buildId: String get() = index.buildId
    private val byId: Map<String, ApiModuleSummary> by lazy { modules.associateBy { it.id } }
    fun find(id: String): ApiModuleSummary? = byId[id]
}
