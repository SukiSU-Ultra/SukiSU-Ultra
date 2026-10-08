package com.sukisu.ultra.data.repository

import org.json.JSONException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RepoModuleParserTest {

    private val ksuJson = """
        [
          {
            "moduleId": "zygisk_assistant",
            "moduleName": "Zygisk Assistant",
            "authors": [{"name": "jijingg", "link": "https://github.com/jijingg"}],
            "summary": "A Zygisk module",
            "metamodule": false,
            "zygisk": true,
            "stargazerCount": 42,
            "updatedAt": "2025-06-01T00:00:00Z",
            "createdAt": "2024-01-01T00:00:00Z",
            "latestRelease": {
              "name": "v2.2",
              "time": "2025-06-01T00:00:00Z",
              "versionCode": 202,
              "downloadUrl": "https://example.com/ZygiskAssistant-v2.2.zip"
            }
          }
        ]
    """.trimIndent()

    private val mmrlJson = """
        {
          "id": "test-repo",
          "name": "Test Repo",
          "modules": [
            {
              "id": "CustomPinyinDictionary",
              "name": "CustomPinyinDictionary for Gboard",
              "version": "v20260101",
              "versionCode": 20260101,
              "author": "wuhgit",
              "description": "Gboard custom pinyin dictionary",
              "support": "https://github.com/wuhgit/CustomPinyinDictionary/issues",
              "readme": "https://raw.githubusercontent.com/wuhgit/CustomPinyinDictionary/main/README.md",
              "timestamp": 1767223192.0,
              "versions": [
                {
                  "timestamp": 1735696699.0,
                  "version": "v20250101",
                  "versionCode": 20250101,
                  "zipUrl": "https://example.com/dict_v20250101.zip",
                  "changelog": "https://example.com/v20250101.md",
                  "size": 31355148
                },
                {
                  "timestamp": 1767223192.0,
                  "version": "v20260101",
                  "versionCode": "20260101",
                  "zipUrl": "https://example.com/dict_v20260101.zip",
                  "changelog": "https://example.com/v20260101.md",
                  "size": 30270378
                }
              ]
            },
            {
              "id": "no_versions_module",
              "name": "No Versions",
              "author": "someone",
              "description": "module without versions"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `sniffFormat detects kernelsu array`() {
        assertEquals(RepoFormat.KERNELSU, RepoModuleParser.sniffFormat(ksuJson))
    }

    @Test
    fun `sniffFormat detects mmrl object`() {
        assertEquals(RepoFormat.MMRL, RepoModuleParser.sniffFormat(mmrlJson))
    }

    @Test
    fun `sniffFormat tolerates BOM and leading whitespace`() {
        assertEquals(RepoFormat.KERNELSU, RepoModuleParser.sniffFormat("\uFEFF\n " + ksuJson))
    }

    @Test
    fun `sniffFormat rejects unknown content`() {
        assertNull(RepoModuleParser.sniffFormat("<html>404</html>"))
        assertNull(RepoModuleParser.sniffFormat("{\"foo\": 1}"))
        assertNull(RepoModuleParser.sniffFormat(""))
    }

    @Test
    fun `parseKsu maps module fields`() {
        val modules = RepoModuleParser.parseKsu(ksuJson, "src1", "Src1")
        assertEquals(1, modules.size)
        val module = modules[0]
        assertEquals("zygisk_assistant", module.moduleId)
        assertEquals("Zygisk Assistant", module.moduleName)
        assertEquals("jijingg", module.authors)
        assertTrue(module.zygisk)
        assertEquals(42, module.stargazerCount)
        assertEquals("v2.2", module.latestRelease)
        assertEquals(202L, module.latestVersionCode)
        assertEquals("src1", module.sourceId)
        assertEquals("Src1", module.sourceName)
        assertNotNull(module.latestAsset)
        assertEquals("ZygiskAssistant-v2.2.zip", module.latestAsset?.name)
    }

    @Test
    fun `parseKsu skips entries without moduleId`() {
        val modules = RepoModuleParser.parseKsu("""[{"moduleName": "broken"}, {"moduleId": "ok"}]""", "", "")
        assertEquals(listOf("ok"), modules.map { it.moduleId })
    }

    @Test
    fun `parseMmrl maps module fields and sorts versions`() {
        val modules = RepoModuleParser.parseMmrl(mmrlJson, "src1", "Src1")
        assertEquals(2, modules.size)
        val dict = modules[0]
        assertEquals("CustomPinyinDictionary", dict.moduleId)
        assertEquals("wuhgit", dict.authors)
        assertEquals(1, dict.authorList.size)
        assertEquals("Gboard custom pinyin dictionary", dict.summary)
        assertEquals("src1", dict.sourceId)
        assertEquals("Src1", dict.sourceName)

        val mmrl = dict.mmrl
        assertNotNull(mmrl)
        assertEquals("https://raw.githubusercontent.com/wuhgit/CustomPinyinDictionary/main/README.md", mmrl!!.readmeUrl)
        assertEquals(2, mmrl.versions.size)
        // highest versionCode first, string versionCode must be tolerated
        assertEquals(20260101L, mmrl.versions[0].versionCode)
        assertEquals("https://example.com/dict_v20260101.zip", mmrl.versions[0].zipUrl)

        assertEquals("v20260101", dict.latestRelease)
        assertEquals(20260101L, dict.latestVersionCode)
        assertEquals("https://example.com/dict_v20260101.zip", dict.latestAsset?.downloadUrl)
        assertEquals(30270378L, dict.latestAsset?.size)
        // epoch seconds -> ISO-8601 UTC
        assertEquals("2025-12-31T23:19:52Z", dict.latestReleaseTime)
        assertEquals(dict.latestReleaseTime, mmrl.versions[0].time)
    }

    @Test
    fun `parseMmrl tolerates modules without versions`() {
        val modules = RepoModuleParser.parseMmrl(mmrlJson, "src1", "Src1")
        val noVersions = modules.first { it.moduleId == "no_versions_module" }
        assertTrue(noVersions.mmrl?.versions.isNullOrEmpty())
        assertEquals("", noVersions.latestRelease)
        assertEquals(0L, noVersions.latestVersionCode)
        assertNull(noVersions.latestAsset)
    }

    @Test
    fun `parseMmrl returns empty list when modules key missing`() {
        assertTrue(RepoModuleParser.parseMmrl("""{"id": "x"}""", "", "").isEmpty())
    }

    @Test
    fun `parse throws on unrecognized format`() {
        try {
            RepoModuleParser.parse("not json", "", "")
            throw AssertionError("expected exception")
        } catch (expected: IllegalArgumentException) {
        }
    }

    @Test
    fun `parse throws on malformed json`() {
        try {
            RepoModuleParser.parse("[broken", "", "")
            throw AssertionError("expected exception")
        } catch (expected: JSONException) {
        }
    }

    @Test
    fun `mmrl module without id is skipped`() {
        val json = """{"modules": [{"name": "no id"}, {"id": "ok"}]}"""
        val modules = RepoModuleParser.parseMmrl(json, "", "")
        assertEquals(listOf("ok"), modules.map { it.moduleId })
    }

    @Test
    fun `parse dispatches by sniffed format`() {
        assertEquals("zygisk_assistant", RepoModuleParser.parse(ksuJson, "s", "S").single().moduleId)
        assertEquals("CustomPinyinDictionary", RepoModuleParser.parse(mmrlJson, "s", "S").first().moduleId)
        assertFalse(RepoModuleParser.parse(mmrlJson, "s", "S").first().zygisk)
    }

    @Test
    fun `parseMmrl leaves assets already on the index host without a fallback`() {
        val module = RepoModuleParser.parseMmrl(
            mmrlJson, "s", "S", "https://example.com/json/modules.json",
        ).first()

        assertTrue(module.mmrl!!.versions.all { it.zipUrlFallback == null })
    }

    @Test
    fun `parseMmrl falls back to the index host when the asset host differs`() {
        val json = """
            {"modules": [{"id": "copg", "versions": [
              {"version": "1.0", "zipUrl": "https://old.example.com/repo/modules/copg/1.0.zip"}
            ]}]}
        """.trimIndent()

        val module = RepoModuleParser.parseMmrl(
            json, "s", "S", "https://new.example.com/repo/json/modules.json",
        ).single()

        assertEquals(
            "https://new.example.com/repo/modules/copg/1.0.zip",
            module.mmrl!!.versions.single().zipUrlFallback,
        )
    }
}
