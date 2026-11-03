package com.sukisu.ultra.ui.util

import java.io.File
import java.util.zip.ZipInputStream
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.Rule

class ThemeVariantEffectiveTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `isAdaptive requires both the flag and the variant`() {
        assertTrue(ThemePackageData(adaptive = true, darkVariant = ThemeVariantData()).isAdaptive)
        assertFalse(ThemePackageData(adaptive = true).isAdaptive)
        assertFalse(ThemePackageData(darkVariant = ThemeVariantData()).isAdaptive)
        assertFalse(ThemePackageData().isAdaptive)
    }

    @Test
    fun `adaptive json decodes and plain json keeps v2 defaults`() {
        val adaptive = json.decodeFromString(
            ThemePackageData.serializer(),
            """
            {
              "version": 3,
              "themeMode": 1,
              "keyColor": 19088743,
              "adaptive": true,
              "darkVariant": { "themeMode": 6, "customBackgroundScrimPercent": -60 }
            }
            """.trimIndent(),
        )
        assertEquals(3, adaptive.version)
        assertTrue(adaptive.isAdaptive)
        assertEquals(6, adaptive.darkVariant?.themeMode)

        val plain = json.decodeFromString(
            ThemePackageData.serializer(),
            """{"version": 2, "themeMode": 2}""",
        )
        assertEquals(ThemePackageStorage.PLAIN_FORMAT_VERSION, plain.version)
        assertFalse(plain.isAdaptive)
        assertNull(plain.darkVariant)

        // Fields written by newer builds are ignored by this parser contract.
        val future = json.decodeFromString(
            ThemePackageData.serializer(),
            """{"version": 2, "someFutureField": true}""",
        )
        assertFalse(future.isAdaptive)
    }

    @Test
    fun `dark flatten overrides base fields and swaps image paths`() {
        val imported = ImportedTheme(
            data = ThemePackageData(
                version = 3,
                themeMode = 1,
                keyColor = 0x11223344,
                customBackgroundScrimPercent = -30,
                hasBackground = true,
                hasCardBackground = false,
                adaptive = true,
                darkVariant = ThemeVariantData(
                    themeMode = 6,
                    keyColor = 0x55667788,
                    customBackgroundScrimPercent = -60,
                ),
            ),
            backgroundPath = "/tmp/light-bg",
            darkBackgroundPath = "/tmp/dark-bg",
            darkStickerPaths = listOf("/tmp/dark-sticker-0"),
        )

        val dark = imported.effectiveFor(dark = true)
        assertEquals(6, dark.data.themeMode)
        assertEquals(0x55667788, dark.data.keyColor)
        assertEquals(-60, dark.data.customBackgroundScrimPercent)
        assertEquals("/tmp/dark-bg", dark.backgroundPath)
        assertEquals(listOf("/tmp/dark-sticker-0"), dark.stickerPaths)
        assertNull(dark.data.adaptive)
        assertNull(dark.data.darkVariant)
        assertFalse(dark.data.isAdaptive)

        // Declared fields the variant does not override keep the base (light) set...
        assertEquals(false, dark.data.hasCardBackground)

        // ...but image presence falls back to the dark entries themselves, so a dark set
        // without its own wallpaper clears it instead of keeping the light image.
        val noDarkBg = imported.copy(darkBackgroundPath = null)
        val darkNoBg = noDarkBg.effectiveFor(dark = true)
        assertEquals(false, darkNoBg.data.hasBackground)
        assertNull(darkNoBg.backgroundPath)
    }

    @Test
    fun `light flatten and non adaptive packages pass the base set through`() {
        val imported = ImportedTheme(
            data = ThemePackageData(
                version = 3,
                themeMode = 1,
                adaptive = true,
                darkVariant = ThemeVariantData(themeMode = 2),
            ),
            backgroundPath = "/tmp/light-bg",
        )

        val light = imported.effectiveFor(dark = false)
        assertEquals(1, light.data.themeMode)
        assertEquals("/tmp/light-bg", light.backgroundPath)
        assertNull(light.data.adaptive)
        assertNull(light.data.darkVariant)

        val plain = ImportedTheme(data = ThemePackageData(themeMode = 2))
        assertEquals(plain, plain.effectiveFor(dark = true))
    }

    @Test
    fun `mergedAdaptiveWith puts the dark side into the variant and rejects adaptive inputs`() {
        val light = ThemePackageData(
            themeMode = 1,
            keyColor = 0x11111111,
            customHomeTitle = "Shared title",
            appIconId = "logo",
        )
        val dark = ThemePackageData(
            themeMode = 6,
            keyColor = 0x22222222,
            customHomeTitle = "Ignored in the variant",
            hasBackground = true,
            homeCardStickerTransforms = listOf(HomeCardStickerTransform()),
        )

        val merged = light.mergedAdaptiveWith(dark)
        assertTrue(merged != null)
        assertEquals(ThemePackageStorage.ADAPTIVE_FORMAT_VERSION, merged!!.version)
        assertEquals(true, merged.adaptive)
        assertTrue(merged.isAdaptive)
        // Shared and light parts stay on the base; the dark half moves into the variant.
        assertEquals(1, merged.themeMode)
        assertEquals("Shared title", merged.customHomeTitle)
        assertEquals("logo", merged.appIconId)
        assertEquals(6, merged.darkVariant?.themeMode)
        assertEquals(0x22222222, merged.darkVariant?.keyColor)
        assertEquals(true, merged.darkVariant?.hasBackground)
        assertEquals(1, merged.darkVariant?.homeCardStickerTransforms?.size)

        val adaptiveSide = light.copy(adaptive = true, darkVariant = ThemeVariantData())
        assertNull(adaptiveSide.mergedAdaptiveWith(dark))
        assertNull(light.mergedAdaptiveWith(adaptiveSide))
    }

    @Test
    fun `adaptive export writes dark entries gated by the variant flags`() = runBlocking {
        val dir = tempFolder.newFolder()
        val background = File(dir, "bg").apply { writeText("light-image") }
        val cardBackground = File(dir, "card").apply { writeText("light-card") }
        val sticker = File(dir, "sticker").apply { writeText("light-sticker") }
        val darkBackground = File(dir, "dark-bg").apply { writeText("dark-image") }
        val darkCardBackground = File(dir, "dark-card").apply { writeText("dark-card") }

        val merged = ThemePackageData(
            hasBackground = true,
            hasCardBackground = true,
            adaptive = true,
            darkVariant = ThemeVariantData(
                themeMode = 6,
                hasBackground = true,
                hasCardBackground = false,
            ),
        )
        val target = File(dir, "merged.sukisu")
        ThemePackageStorage.exportToFile(
            file = target,
            data = merged,
            backgroundFile = background,
            cardBackgroundFile = cardBackground,
            cardStickerFiles = listOf(sticker),
            darkBackgroundFile = darkBackground,
            darkCardBackgroundFile = darkCardBackground,
        ).getOrThrow()

        val entries = readPackageEntryNames(target)
        assertTrue(entries.contains("theme.json"))
        assertTrue(entries.contains("background"))
        assertTrue(entries.contains("card_background"))
        assertTrue(entries.contains("card_sticker_0"))
        assertTrue(entries.contains("background_dark"))
        // Declared false in the variant: the file is present but must not be packed.
        assertFalse(entries.contains("card_background_dark"))
        assertFalse(entries.contains("card_sticker_dark_0"))

        val text = entriesJsonOf(target)
        assertTrue(text.contains("\"adaptive\":true"))
        assertTrue(text.contains("\"darkVariant\""))
        assertTrue(text.contains("\"version\":${ThemePackageStorage.ADAPTIVE_FORMAT_VERSION}"))
    }

    private fun readPackageEntryNames(file: File): List<String> {
        val names = mutableListOf<String>()
        ThemePackageCrypto.decryptingStream(file.inputStream()).use { decrypted ->
            ZipInputStream(decrypted).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    names += entry.name
                    entry = zip.nextEntry
                }
            }
        }
        return names
    }

    private fun entriesJsonOf(file: File): String {
        ThemePackageCrypto.decryptingStream(file.inputStream()).use { decrypted ->
            ZipInputStream(decrypted).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    if (entry.name == "theme.json") {
                        return zip.readBytes().toString(Charsets.UTF_8)
                    }
                }
            }
        }
        error("theme.json missing")
    }
}
