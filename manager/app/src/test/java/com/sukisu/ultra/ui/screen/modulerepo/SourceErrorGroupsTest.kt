package com.sukisu.ultra.ui.screen.modulerepo

import org.junit.Assert.assertEquals
import org.junit.Test

class SourceErrorGroupsTest {

    @Test
    fun `sources failing the same way share one group`() {
        val groups = groupSourceErrors(
            linkedMapOf(
                "KernelSU" to "HTTP 404",
                "uonou.github.io" to "HTTP 404",
            )
        )

        assertEquals(1, groups.size)
        assertEquals(listOf("KernelSU", "uonou.github.io"), groups[0].names)
        assertEquals("HTTP 404", groups[0].message)
    }

    @Test
    fun `different failures become separate groups in first-seen order`() {
        val groups = groupSourceErrors(
            linkedMapOf(
                "KernelSU" to "HTTP 404",
                "uonou.github.io" to "connection closed",
                "ShizuSU" to "HTTP 404",
            )
        )

        assertEquals(2, groups.size)
        assertEquals(SourceErrorGroup(listOf("KernelSU", "ShizuSU"), "HTTP 404"), groups[0])
        assertEquals(SourceErrorGroup(listOf("uonou.github.io"), "connection closed"), groups[1])
    }

    @Test
    fun `a single failure keeps its source name`() {
        val groups = groupSourceErrors(mapOf("KernelSU" to "HTTP 404"))

        assertEquals(listOf(SourceErrorGroup(listOf("KernelSU"), "HTTP 404")), groups)
    }

    @Test
    fun `no failures means no notices`() {
        assertEquals(emptyList<SourceErrorGroup>(), groupSourceErrors(emptyMap()))
    }
}
