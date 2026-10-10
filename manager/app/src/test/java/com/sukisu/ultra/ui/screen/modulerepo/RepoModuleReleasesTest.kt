package com.sukisu.ultra.ui.screen.modulerepo

import com.sukisu.ultra.data.model.MmrlModuleInfo
import com.sukisu.ultra.data.model.MmrlVersion
import com.sukisu.ultra.data.model.ReleaseAsset
import com.sukisu.ultra.data.model.RepoModule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RepoModuleReleasesTest {

    private fun module(
        latestRelease: String = "",
        latestReleaseTime: String = "",
        latestAsset: ReleaseAsset? = null,
        mmrl: MmrlModuleInfo? = null,
    ) = RepoModule(
        moduleId = "m",
        moduleName = "Module",
        authors = "",
        authorList = emptyList(),
        summary = "",
        metamodule = false,
        stargazerCount = 0,
        updatedAt = "",
        createdAt = "",
        latestRelease = latestRelease,
        latestReleaseTime = latestReleaseTime,
        latestVersionCode = 0,
        latestAsset = latestAsset,
        sourceId = "source",
        sourceName = "Source",
        mmrl = mmrl,
    )

    @Test
    fun `an mmrl index contributes one release per version`() {
        val mmrl = MmrlModuleInfo(
            readmeUrl = null,
            supportUrl = null,
            versions = listOf(
                MmrlVersion(
                    version = "2.0",
                    versionCode = 2,
                    timestamp = 0,
                    time = "2026-01-02T00:00:00Z",
                    zipUrl = "https://example.com/modules/m/2.0.zip",
                    zipUrlFallback = "https://example.com/fallback/2.0.zip",
                    changelogUrl = "https://example.com/changelog.md",
                    size = 10,
                ),
                MmrlVersion(
                    version = "1.0",
                    versionCode = 1,
                    timestamp = 0,
                    time = "2026-01-01T00:00:00Z",
                    zipUrl = "https://example.com/modules/m/1.0.zip",
                    zipUrlFallback = null,
                    changelogUrl = null,
                    size = 5,
                ),
            ),
        )
        val releases = repoModuleReleases(module(mmrl = mmrl))

        assertEquals(listOf("2.0", "1.0"), releases.map { it.name })
        val newest = releases.first()
        assertEquals("2.0.zip", newest.assets.single().name)
        assertEquals("https://example.com/modules/m/2.0.zip", newest.assets.single().downloadUrl)
        assertEquals("https://example.com/fallback/2.0.zip", newest.assets.single().downloadUrlFallback)
        assertEquals("https://example.com/changelog.md", newest.changelogUrl)
        assertEquals(10L, newest.assets.single().size)
    }

    @Test
    fun `a kernel su index contributes the newest release so the module stays installable`() {
        val releases = repoModuleReleases(
            module(
                latestRelease = "v1.5.0",
                latestReleaseTime = "2026-09-20T04:19:50Z",
                latestAsset = ReleaseAsset(
                    name = "Zygisk-Next-1.5.0-release.zip",
                    downloadUrl = "https://github.com/LSPosed/ZygiskNext/releases/download/v1.5.0/Zygisk-Next-1.5.0-release.zip",
                    size = 0,
                ),
            )
        )

        assertEquals(1, releases.size)
        val release = releases.single()
        assertEquals("v1.5.0", release.name)
        assertEquals("v1.5.0", release.tagName)
        assertEquals("2026-09-20T04:19:50Z", release.publishedAt)
        assertEquals("Zygisk-Next-1.5.0-release.zip", release.assets.single().name)
        assertEquals(
            "https://github.com/LSPosed/ZygiskNext/releases/download/v1.5.0/Zygisk-Next-1.5.0-release.zip",
            release.assets.single().downloadUrl,
        )
    }

    @Test
    fun `a kernel su module without a download address contributes nothing`() {
        assertTrue(repoModuleReleases(module(latestRelease = "v1.0")).isEmpty())
    }

    @Test
    fun `an mmrl module without versions contributes nothing`() {
        val mmrl = MmrlModuleInfo(readmeUrl = null, supportUrl = null, versions = emptyList())
        assertTrue(repoModuleReleases(module(mmrl = mmrl)).isEmpty())
    }
}
