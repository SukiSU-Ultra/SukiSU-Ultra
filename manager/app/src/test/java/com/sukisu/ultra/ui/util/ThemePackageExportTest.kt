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
            }
        } finally {
            file.delete()
        }
    }
}
