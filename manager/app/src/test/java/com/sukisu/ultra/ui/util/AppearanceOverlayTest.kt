package com.sukisu.ultra.ui.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class AppearanceOverlayTest {

    @Test
    fun resolvesSharedThenModeSpecificTokens() {
        val parsed = AppearanceOverlayStore.parse(
            """
            {
              "schema": 1,
              "colors": {
                "shared": { "textPrimary": "#FFFFFFFF", "accent": "#FF112233" },
                "light": { "textPrimary": "#FF111111" },
                "dark": { "textSecondary": "#FFEEEEEE" }
              }
            }
            """.trimIndent(),
        ).getOrThrow()

        val light = parsed.resolved.colorsFor(dark = false)
        assertEquals(0xFF111111.toInt(), light.values[AppearanceColorToken.TEXT_PRIMARY])
        assertEquals(0xFF112233.toInt(), light.values[AppearanceColorToken.ACCENT])

        val dark = parsed.resolved.colorsFor(dark = true)
        assertEquals(0xFFFFFFFF.toInt(), dark.values[AppearanceColorToken.TEXT_PRIMARY])
        assertEquals(0xFFEEEEEE.toInt(), dark.values[AppearanceColorToken.TEXT_SECONDARY])
    }

    @Test
    fun acceptsSixAndEightDigitColors() {
        val parsed = AppearanceOverlayStore.parse(
            """{ "colors": { "shared": { "textPrimary": "#123456", "textSecondary": "#80123456" } } }""",
        ).getOrThrow()

        val colors = parsed.resolved.colorsFor(dark = false)
        assertEquals(0xFF123456.toInt(), colors.values[AppearanceColorToken.TEXT_PRIMARY])
        assertEquals(0x80123456.toInt(), colors.values[AppearanceColorToken.TEXT_SECONDARY])
    }

    @Test
    fun rejectsInvalidColorWithTokenPath() {
        val error = AppearanceOverlayStore.parse(
            """{ "colors": { "dark": { "textPrimary": "#12345" } } }""",
        ).exceptionOrNull()

        assertTrue(error?.message.orEmpty().contains("colors.dark.textPrimary"))
    }

    @Test
    fun rejectsUnknownKeys() {
        val result = AppearanceOverlayStore.parse(
            """{ "colors": { "shared": { "textPrimary": "#FFFFFFFF" } }, "dynamic": true }""",
        )

        assertTrue(result.isFailure)
    }

    @Test
    fun clampsImageEffectsToStaticRanges() {
        val parsed = AppearanceOverlayStore.parse(
            """
            {
              "image": {
                "background": {
                  "sharpen": 500,
                  "saturation": -10,
                  "contrast": 400,
                  "brightness": 999
                }
              }
            }
            """.trimIndent(),
        ).getOrThrow()

        val effects = parsed.resolved.background!!
        assertEquals(100f, effects.sharpen)
        assertEquals(20f, effects.saturation)
        assertEquals(200f, effects.contrast)
        assertEquals(100f, effects.brightness)
    }

    @Test
    fun rejectsNonFiniteEffectValues() {
        assertTrue(
            AppearanceOverlayStore.parse(
                """{ "image": { "background": { "sharpen": "NaN" } } }""",
            ).isFailure,
        )
    }

    @Test
    fun mergeKeepsUnselectedSections() {
        val current = AppearanceOverlayData(
            colors = AppearanceColorsData(
                shared = ColorTokensData(textPrimary = "#FFFFFFFF"),
            ),
            image = AppearanceImageData(
                background = ImageEffectsData(sharpen = 20f),
            ),
        )
        val incoming = AppearanceOverlayData(
            colors = AppearanceColorsData(
                shared = ColorTokensData(textPrimary = "#FF000000"),
            ),
            image = AppearanceImageData(
                background = ImageEffectsData(contrast = 120f),
            ),
        )

        val colorsOnly = AppearanceOverlayStore.merge(current, incoming, true, false)!!
        assertEquals("#FF000000", colorsOnly.colors?.shared?.textPrimary)
        assertEquals(20f, colorsOnly.image?.background?.sharpen)

        val effectsOnly = AppearanceOverlayStore.merge(current, incoming, false, true)!!
        assertEquals("#FFFFFFFF", effectsOnly.colors?.shared?.textPrimary)
        assertEquals(120f, effectsOnly.image?.background?.contrast)

        val cleared = AppearanceOverlayStore.merge(current, AppearanceOverlayData(), true, false)
        assertNull(cleared?.colors)
        assertEquals(20f, cleared?.image?.background?.sharpen)
    }

    @Test
    fun canonicalJsonSkipsNullSections() {
        val encoded = AppearanceOverlayStore.encode(
            AppearanceOverlayData(
                colors = AppearanceColorsData(
                    shared = ColorTokensData(textPrimary = "#FFFFFFFF"),
                ),
            ),
        )

        assertFalse(encoded.contains("image"))
        assertEquals(
            "#FFFFFFFF",
            AppearanceOverlayStore.parse(encoded).getOrThrow().data.colors?.shared?.textPrimary,
        )
    }

    @Test
    fun readTextStopsAtSizeLimit() {
        val tooLarge = ByteArray(AppearanceOverlayStore.MAX_BYTES + 1) { 'a'.code.toByte() }
        assertTrue(
            runCatching {
                AppearanceOverlayStore.readText(ByteArrayInputStream(tooLarge))
            }.isFailure,
        )
    }

    @Test
    fun prettyJsonRoundTrips() {
        val data = AppearanceOverlayData(
            image = AppearanceImageData(
                background = ImageEffectsData(sharpen = 35f, saturation = 105f),
            ),
        )
        val parsed = AppearanceOverlayStore.parse(
            AppearanceOverlayStore.encodePretty(data),
        ).getOrThrow()

        assertEquals(35f, parsed.resolved.background?.sharpen)
        assertEquals(105f, parsed.resolved.background?.saturation)
    }

    @Test
    fun colorEditsAreScopedAndNeedNoEmptySections() {
        val shared = AppearanceOverlayData()
            .withColorToken(AppearanceColorMode.SHARED, AppearanceColorToken.TEXT_PRIMARY, "#FFFFFFFF")
        assertEquals(
            "#FFFFFFFF",
            shared.colorTokenValue(AppearanceColorMode.SHARED, AppearanceColorToken.TEXT_PRIMARY),
        )

        val light = shared.withColorToken(
            AppearanceColorMode.LIGHT,
            AppearanceColorToken.TEXT_PRIMARY,
            "#FF111111",
        )
        assertEquals(
            "#FF111111",
            light.colorTokenValue(AppearanceColorMode.LIGHT, AppearanceColorToken.TEXT_PRIMARY),
        )
        assertEquals(
            "#FFFFFFFF",
            light.colorTokenValue(AppearanceColorMode.SHARED, AppearanceColorToken.TEXT_PRIMARY),
        )
        assertEquals(
            AppearanceColorMode.LIGHT,
            light.effectiveColorToken(AppearanceColorMode.LIGHT, AppearanceColorToken.TEXT_PRIMARY)?.first,
        )

        val lightCleared = light.withColorToken(
            AppearanceColorMode.LIGHT,
            AppearanceColorToken.TEXT_PRIMARY,
            null,
        )
        assertEquals(
            AppearanceColorMode.SHARED,
            lightCleared.effectiveColorToken(
                AppearanceColorMode.LIGHT,
                AppearanceColorToken.TEXT_PRIMARY,
            )?.first,
        )

        val empty = lightCleared.withColorToken(
            AppearanceColorMode.SHARED,
            AppearanceColorToken.TEXT_PRIMARY,
            null,
        )
        assertNull(empty.colors)
    }

    @Test
    fun imageEffectEditsNormalizeToNull() {
        val enabled = AppearanceOverlayData().withImageEffect(AppearanceEffectKey.SHARPEN, 30f)
        assertEquals(30f, enabled.imageEffectValue(AppearanceEffectKey.SHARPEN))
        assertNull(
            enabled.withImageEffect(AppearanceEffectKey.SHARPEN, null).image,
        )
    }

    @Test
    fun colorStringRoundTrips() {
        val argb = 0x80123456.toInt()
        assertEquals(argb, AppearanceOverlayStore.parseColorValue(argb.toOverlayColorString()))
    }
}
