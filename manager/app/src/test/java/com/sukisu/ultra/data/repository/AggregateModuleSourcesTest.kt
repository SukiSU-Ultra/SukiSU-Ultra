package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.RepoModule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AggregateModuleSourcesTest {

    private fun module(id: String, sourceId: String, sourceName: String) = RepoModule(
        moduleId = id,
        moduleName = "name:$id",
        authors = "",
        authorList = emptyList(),
        summary = "",
        metamodule = false,
        stargazerCount = 0,
        updatedAt = "",
        createdAt = "",
        latestRelease = "",
        latestReleaseTime = "",
        latestVersionCode = 0,
        latestAsset = null,
        sourceId = sourceId,
        sourceName = sourceName,
    )

    private val sourceA = RepoSource(id = "a", name = "RepoA", url = "https://a.example.com/json/modules.json")
    private val sourceB = RepoSource(id = "b", name = "RepoB", url = "https://b.example.com/json/modules.json")

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
}
