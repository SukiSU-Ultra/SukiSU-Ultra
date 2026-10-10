package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RepoCandidatesTest {

    @Test
    fun `candidates are ordered by module count, most first`() {
        val counts = defaultRepoCandidates.map { it.moduleCount }
        assertEquals(counts.sortedDescending(), counts)
    }

    @Test
    fun `every candidate points at a concrete index file`() {
        defaultRepoCandidates.forEach { candidate ->
            assertTrue(
                "${candidate.name} should be https",
                candidate.url.startsWith("https://"),
            )
            // A .json address is used as-is by addSource, so adding a candidate never has to probe
            // for the index and never depends on a Pages site being deployed.
            assertTrue(
                "${candidate.name} should point at a .json file",
                candidate.url.endsWith(".json"),
            )
            assertTrue("${candidate.name} should list modules", candidate.moduleCount > 0)
            assertTrue("${candidate.name} needs a name", candidate.name.isNotBlank())
        }
    }

    @Test
    fun `no repository is offered twice`() {
        val urls = defaultRepoCandidates.map { it.url }
        assertEquals(urls.size, urls.toSet().size)

        // Hosts outside GitHub have no identity to compare, so only the known ones are checked.
        val identities = defaultRepoCandidates.mapNotNull { indexIdentity(it.url) }
        assertEquals(identities.size, identities.toSet().size)

        val names = defaultRepoCandidates.map { it.name }
        assertEquals(names.size, names.toSet().size)
    }

    @Test
    fun `a candidate is not offered again once it is configured`() {
        val sources = listOf(
            RepoSource(
                id = "a",
                name = "uonou/mmrl-repo",
                url = "https://uonou.github.io/mmrl-repo/json/modules.json",
            ),
        )
        val uonou = defaultRepoCandidates.first { it.name == "uonou/mmrl-repo" }
        val andere = defaultRepoCandidates.first { it.name == "ZG-R" }

        assertTrue(isSameSource(sources.single().url, uonou.url))
        assertTrue(!isSameSource(sources.single().url, andere.url))
    }

    @Test
    fun `a candidate configured through the repository address is recognised`() {
        val other = defaultRepoCandidates.first { it.name == "ZG-R" }
        // What a user gets by pasting the repository address instead of the index address.
        val stored = "https://raw.githubusercontent.com/ZGUATION-PROJECTS/ZG-R/HEAD/json/modules.json"
        assertTrue(isSameSource(stored, other.url))
    }
}
