package com.sukisu.ultra.ui.screen.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AiWebControllerTest {

    @Test
    fun parsesDuckDuckGoHtmlResultsAndRedirects() {
        val html = """
            <div class="result results_links">
              <a rel="nofollow" class="result__a"
                 href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Fowner%2Frepo&amp;rut=abc">
                 Owner / Repo &amp; friends
              </a>
              <a class="result__snippet" href="#">A KernelSU module &amp; tools</a>
            </div>
            <div class="result results_links">
              <a rel="nofollow" class="result__a" href="https://example.com/module">Example module</a>
              <a class="result__snippet" href="#">Second result</a>
            </div>
        """.trimIndent()

        val results = AiWebController.parseDuckDuckGo(html)

        assertEquals(2, results.size)
        assertEquals("Owner / Repo & friends", results[0].title)
        assertEquals("https://github.com/owner/repo", results[0].url)
        assertEquals("A KernelSU module & tools", results[0].snippet)
        assertEquals("https://example.com/module", results[1].url)
    }

    @Test
    fun parsesDuckDuckGoLiteResults() {
        val html = """
            <a rel="nofollow" href="https://example.com/module" class="result-link">Example Module</a>
            <td class="result-snippet">A module from the web</td>
        """.trimIndent()

        val results = AiWebController.parseDuckDuckGoLite(html)

        assertEquals(1, results.size)
        assertEquals("Example Module", results[0].title)
        assertEquals("https://example.com/module", results[0].url)
        assertEquals("A module from the web", results[0].snippet)
    }

    @Test
    fun acceptsOnlyGithubReleaseDownloadUrls() {
        assertTrue(
            AiWebController.isGithubReleaseUrl(
                "https://github.com/owner/repo/releases/download/v1.0/module.zip"
            )
        )
        assertFalse(AiWebController.isGithubReleaseUrl("https://example.com/module.zip"))
        assertFalse(AiWebController.isGithubReleaseUrl("http://github.com/owner/repo/releases/download/v1.0/module.zip"))
    }
}
