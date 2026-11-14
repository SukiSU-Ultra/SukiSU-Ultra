package com.sukisu.ultra.ui.util

import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.ZipInputStream
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemePackageExportTest {

    private val json = Json {
        ignoreUnknownKeys = true
    }

    @Test
    fun exportsEncryptedV4PackageWithAppearance() = runBlocking {
        val file = File.createTempFile("sukisu-theme-export", ".sukisu")
        try {
            val data = ThemePackageData(
                version = ThemePackageStorage.APPEARANCE_VERSION,
                appearance = AppearanceOverlayData(
                    colors = AppearanceColorsData(
                        shared = ColorTokensData(textPrimary = "#FFFFFFFF"),
                    ),
                    image = AppearanceImageData(
                        background = ImageEffectsData(sharpen = 30f),
                    ),
                ),
                homeLayout = "classic",
                homeStatusAlignment = "end",
                homeStatusScale = 1.15f,
                homePillScale = 1.2f,
                homeStatusWidthFraction = 0.8f,
                homeCardImageStyle = "banner",
                showHomeCardImageWithoutBackground = true,
            )

            ThemePackageStorage.exportToFile(file = file, data = data, backgroundFile = null)
                .getOrThrow()

            val encrypted = file.readBytes()
            assertTrue(ThemePackageCrypto.hasValidHeader(encrypted))
            val plain = ThemePackageCrypto.decrypt(encrypted)

            ZipInputStream(ByteArrayInputStream(plain)).use { zip ->
                val entry = zip.nextEntry
                assertEquals("theme.json", entry?.name)
                val decoded = json.decodeFromString(
                    ThemePackageData.serializer(),
                    zip.readBytes().toString(Charsets.UTF_8),
                )
                assertEquals(ThemePackageStorage.APPEARANCE_VERSION, decoded.version)
                assertEquals(
                    "#FFFFFFFF",
                    decoded.appearance?.colors?.shared?.textPrimary,
                )
                assertEquals(30f, decoded.appearance?.image?.background?.sharpen ?: 0f)
                assertEquals("classic", decoded.homeLayout)
                assertEquals("end", decoded.homeStatusAlignment)
                assertEquals(1.15f, decoded.homeStatusScale ?: 0f, 0f)
                assertEquals(1.2f, decoded.homePillScale ?: 0f, 0f)
                assertEquals(0.8f, decoded.homeStatusWidthFraction ?: 0f, 0f)
                assertEquals("banner", decoded.homeCardImageStyle)
                assertEquals(true, decoded.showHomeCardImageWithoutBackground)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun exportsV5PackageForImmersiveHome() = runBlocking {
        val file = File.createTempFile("sukisu-theme-export", ".sukisu")
        try {
            val data = ThemePackageData(
                homeLayout = "immersive",
                homeStatusAlignment = "end",
                homeStatusScale = 1.5f,
                homePillScale = 1.2f,
                homeStatusWidthFraction = 0.8f,
                homeCardImageStyle = "banner",
                showHomeCardImageWithoutBackground = true,
            )

            ThemePackageStorage.exportToFile(file = file, data = data, backgroundFile = null)
                .getOrThrow()

            val plain = ThemePackageCrypto.decrypt(file.readBytes())
            ZipInputStream(ByteArrayInputStream(plain)).use { zip ->
                val entry = zip.nextEntry
                assertEquals("theme.json", entry?.name)
                val decoded = json.decodeFromString(
                    ThemePackageData.serializer(),
                    zip.readBytes().toString(Charsets.UTF_8),
                )
                assertEquals(ThemePackageStorage.HOME_STATUS_VERSION, decoded.version)
                assertEquals("immersive", decoded.homeLayout)
                assertEquals("end", decoded.homeStatusAlignment)
                assertEquals(1.5f, decoded.homeStatusScale ?: 0f, 0f)
                assertEquals(1.2f, decoded.homePillScale ?: 0f, 0f)
                assertEquals(0.8f, decoded.homeStatusWidthFraction ?: 0f, 0f)
                assertEquals("banner", decoded.homeCardImageStyle)
            }
        } finally {
            file.delete()
        }
    }
}
