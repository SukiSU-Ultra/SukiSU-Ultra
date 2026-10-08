package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.ReleaseAsset
import com.sukisu.ultra.data.model.RepoModule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AggregateModuleSourcesTest {

    private fun module(
        id: String,
        sourceId: String,
        sourceName: String,
        name: String = "name:$id",
        versionCode: Long = 0,
        downloadUrl: String? = null,
    ) = RepoModule(
        moduleId = id,
        moduleName = name,
        authors = "",
        authorList = emptyList(),
        summary = "",
        metamodule = false,
        stargazerCount = 0,
        updatedAt = "",
        createdAt = "",
        latestRelease = "",
        latestReleaseTime = "",
        latestVersionCode = versionCode,
        latestAsset = downloadUrl?.let { ReleaseAsset(name = "m.zip", downloadUrl = it, size = 0L) },
        sourceId = sourceId,
        sourceName = sourceName,
    )

    private val sourceA = RepoSource(id = "a", name = "RepoA", url = "https://a.example.com/json/modules.json")
    private val sourceB = RepoSource(id = "b", name = "RepoB", url = "https://b.example.com/json/modules.json")
    private val sourceC = RepoSource(id = "c", name = "RepoC", url = "https://c.example.com/json/modules.json")

    @Test
    fun `merges modules from all sources`() {
        val outcomes = listOf(
            Result.success(listOf(module("m1", "a", "RepoA"))),
            Result.success(listOf(module("m2", "b", "RepoB"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertEquals(listOf("m1", "m2"), result.modules.map { it.moduleId })
        assertTrue(result.sourceErrors.isEmpty())
    }

    @Test
    fun `first source wins on duplicate module id`() {
        val outcomes = listOf(
            Result.success(listOf(module("dup", "a", "RepoA"))),
            Result.success(listOf(module("dup", "b", "RepoB"), module("only-b", "b", "RepoB"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertEquals(listOf("dup", "only-b"), result.modules.map { it.moduleId })
        assertEquals("a", result.modules.first().sourceId)
    }

    @Test
    fun `failed source records error and does not block others`() {
        val failure = Result.failure<List<RepoModule>>(IllegalStateException("HTTP 404"))
        val outcomes = listOf(failure, Result.success(listOf(module("m2", "b", "RepoB"))))
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertEquals(listOf("m2"), result.modules.map { it.moduleId })
        assertEquals(mapOf("RepoA" to "HTTP 404"), result.sourceErrors)
    }

    @Test
    fun `all sources failed yields empty modules with errors`() {
        val outcomes = listOf(
            Result.failure<List<RepoModule>>(IllegalStateException("HTTP 404")),
            Result.failure<List<RepoModule>>(IllegalStateException("unrecognized format")),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertTrue(result.modules.isEmpty())
        assertEquals(
            mapOf("RepoA" to "HTTP 404", "RepoB" to "unrecognized format"),
            result.sourceErrors
        )
    }

    @Test
    fun `outcome list shorter than sources is tolerated`() {
        val result = aggregateModuleSources(listOf(sourceA, sourceB), emptyList())
        assertTrue(result.modules.isEmpty())
        assertTrue(result.sourceErrors.isEmpty())
    }

    @Test
    fun `ids differing only in case are the same module`() {
        val outcomes = listOf(
            Result.success(listOf(module("copg", "a", "RepoA", name = "COPG SPOOF"))),
            Result.success(listOf(module("COPG", "b", "RepoB", name = "COPG SPOOF"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertEquals(1, result.modules.size)
        assertEquals("copg", result.modules.single().moduleId)
        assertEquals(listOf("RepoB"), result.modules.single().alternateSourceNames)
    }

    @Test
    fun `differently spelled ids with the same name are the same module`() {
        val outcomes = listOf(
            Result.success(listOf(module("trickystore", "a", "RepoA", name = "Tricky Store"))),
            Result.success(listOf(module("tricky_store", "b", "RepoB", name = "Tricky Store"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertEquals(1, result.modules.size)
        assertEquals("trickystore", result.modules.single().moduleId)
    }

    @Test
    fun `same id under different names is the same module`() {
        val outcomes = listOf(
            Result.success(listOf(module("susfs", "a", "RepoA", name = "SUSFS For KernelSU"))),
            Result.success(listOf(module("susfs", "b", "RepoB", name = "SUSFS"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        assertEquals(1, result.modules.size)
        assertEquals("SUSFS For KernelSU", result.modules.single().moduleName)
    }

    @Test
    fun `installable entry wins over one without a download address`() {
        val outcomes = listOf(
            Result.success(listOf(module("m", "a", "RepoA", versionCode = 9))),
            Result.success(listOf(module("m", "b", "RepoB", versionCode = 1, downloadUrl = "https://b/m.zip"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        val merged = result.modules.single()
        assertEquals("b", merged.sourceId)
        assertEquals("https://b/m.zip", merged.latestAsset?.downloadUrl)
        assertEquals(listOf("RepoA"), merged.alternateSourceNames)
    }

    @Test
    fun `newer version wins regardless of source order`() {
        val outcomes = listOf(
            Result.success(listOf(module("m", "a", "RepoA", versionCode = 1, downloadUrl = "https://a/m.zip"))),
            Result.success(listOf(module("m", "b", "RepoB", versionCode = 7, downloadUrl = "https://b/m.zip"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        val merged = result.modules.single()
        assertEquals("b", merged.sourceId)
        assertEquals(listOf("RepoA"), merged.alternateSourceNames)
    }

    @Test
    fun `older duplicate does not displace the newer entry when it comes second`() {
        val outcomes = listOf(
            Result.success(listOf(module("m", "b", "RepoB", versionCode = 7, downloadUrl = "https://b/m.zip"))),
            Result.success(listOf(module("m", "a", "RepoA", versionCode = 1, downloadUrl = "https://a/m.zip"))),
        )
        val result = aggregateModuleSources(listOf(sourceB, sourceA), outcomes)
        val merged = result.modules.single()
        assertEquals("b", merged.sourceId)
        assertEquals(listOf("RepoA"), merged.alternateSourceNames)
    }

    @Test
    fun `module published by three sources keeps both alternates`() {
        val outcomes = listOf(
            Result.success(listOf(module("m", "a", "RepoA", versionCode = 3, downloadUrl = "https://a/m.zip"))),
            Result.success(listOf(module("m", "b", "RepoB", versionCode = 1, downloadUrl = "https://b/m.zip"))),
            Result.success(listOf(module("m", "c", "RepoC", versionCode = 2, downloadUrl = "https://c/m.zip"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB, sourceC), outcomes)
        val merged = result.modules.single()
        assertEquals("a", merged.sourceId)
        assertEquals(listOf("RepoB", "RepoC"), merged.alternateSourceNames)
    }

    @Test
    fun `an entry that already carries alternates keeps them when it wins again`() {
        val outcomes = listOf(
            Result.success(
                listOf(
                    module("m", "a", "RepoA", versionCode = 5, downloadUrl = "https://a/m.zip")
                        .copy(alternateSourceNames = listOf("RepoC"))
                )
            ),
            Result.success(listOf(module("m", "b", "RepoB", versionCode = 1, downloadUrl = "https://b/m.zip"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        val merged = result.modules.single()
        assertEquals("a", merged.sourceId)
        assertEquals(listOf("RepoC", "RepoB"), merged.alternateSourceNames)
    }

    @Test
    fun `a module is never listed as an alternate of itself`() {
        val outcomes = listOf(
            Result.success(
                listOf(
                    module("m", "a", "RepoA", versionCode = 1, downloadUrl = "https://a/m.zip"),
                    module("m", "a", "RepoA", versionCode = 2, downloadUrl = "https://a/m.zip"),
                )
            ),
        )
        val result = aggregateModuleSources(listOf(sourceA), outcomes)
        val merged = result.modules.single()
        assertEquals(2, merged.latestVersionCode)
        assertTrue(merged.alternateSourceNames.isEmpty())
    }

    @Test
    fun `modules sharing a name across sources are treated as one`() {
        val outcomes = listOf(
            Result.success(
                listOf(
                    module("busybox-a", "a", "RepoA", name = "BusyBox"),
                    module("busybox-b", "b", "RepoB", name = "BusyBox"),
                    module("other", "b", "RepoB", name = "Something Else"),
                )
            ),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB), outcomes)
        // The two BusyBox entries share a name, so they are one module; the third stands alone.
        assertEquals(listOf("busybox-a", "other"), result.modules.map { it.moduleId })
    }

    @Test
    fun `modules with no name fall back to being matched by id`() {
        val outcomes = listOf(
            Result.success(listOf(module("anon", "a", "RepoA", name = ""))),
            Result.success(listOf(module("anon", "b", "RepoB", name = ""))),
            Result.success(listOf(module("other", "c", "RepoC", name = ""))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB, sourceC), outcomes)
        assertEquals(listOf("anon", "other"), result.modules.map { it.moduleId })
    }

    @Test
    fun `dedup keeps the position of the first source in the list`() {
        val outcomes = listOf(
            Result.success(listOf(module("first", "a", "RepoA"))),
            Result.success(listOf(module("dup", "b", "RepoB"), module("last", "b", "RepoB"))),
            Result.success(listOf(module("dup", "c", "RepoC", versionCode = 4, downloadUrl = "https://c/m.zip"))),
        )
        val result = aggregateModuleSources(listOf(sourceA, sourceB, sourceC), outcomes)
        assertEquals(listOf("first", "dup", "last"), result.modules.map { it.moduleId })
        assertEquals("c", result.modules[1].sourceId)
    }
}
