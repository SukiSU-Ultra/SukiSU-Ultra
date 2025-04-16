package zako.zako.zako.ui.theme

import androidx.compose.ui.graphics.Color

sealed class ThemeColors {
    abstract val Primary: Color
    abstract val Secondary: Color
    abstract val Tertiary: Color
    abstract val OnPrimary: Color
    abstract val OnSecondary: Color
    abstract val OnTertiary: Color
    abstract val PrimaryContainer: Color
    abstract val SecondaryContainer: Color
    abstract val TertiaryContainer: Color
    abstract val OnPrimaryContainer: Color
    abstract val OnSecondaryContainer: Color
    abstract val OnTertiaryContainer: Color
    abstract val ButtonContrast: Color

    open fun getCustomSliderActiveColor(): Color = Primary
    open fun getCustomSliderInactiveColor(): Color = PrimaryContainer

    // Default Theme (white)
    object Default : ThemeColors() {
        override val Primary = Color(0xFFFFFFFF)
        override val Secondary = Color(0xFFF5F5F5)
        override val Tertiary = Color(0xFFE0E0E0)
        override val OnPrimary = Color(0xFF616161)
        override val OnSecondary = Color(0xFF616161)
        override val OnTertiary = Color(0xFF616161)
        override val PrimaryContainer = Color(0xFFF5F5F5)
        override val SecondaryContainer = Color(0xFFEEEEEE)
        override val TertiaryContainer = Color(0xFFE0E0E0)
        override val OnPrimaryContainer = Color(0xFF000000)
        override val OnSecondaryContainer = Color(0xFF000000)
        override val OnTertiaryContainer = Color(0xFF000000)
        override val ButtonContrast = Color(0xFF00BFFF)
    }

    // Blue Theme
    object Blue : ThemeColors() {
        override val Primary = Color(0xFF2196F3)
        override val Secondary = Color(0xFF1E88E5)
        override val Tertiary = Color(0xFF0D47A1)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFCBE6FC)
        override val SecondaryContainer = Color(0xFFBBDEFB)
        override val TertiaryContainer = Color(0xFF90CAF9)
        override val OnPrimaryContainer = Color(0xFF0A1A2E)
        override val OnSecondaryContainer = Color(0xFF0A192D)
        override val OnTertiaryContainer = Color(0xFF071B3D)
        override val ButtonContrast = Color(0xFF00BFFF)
    }

    // Green Theme
    object Green : ThemeColors() {
        override val Primary = Color(0xFF4CAF50)
        override val Secondary = Color(0xFF43A047)
        override val Tertiary = Color(0xFF1B5E20)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFC8E6C9)
        override val SecondaryContainer = Color(0xFFA5D6A7)
        override val TertiaryContainer = Color(0xFF81C784)
        override val OnPrimaryContainer = Color(0xFF0A1F0B)
        override val OnSecondaryContainer = Color(0xFF0A1D0B)
        override val OnTertiaryContainer = Color(0xFF071F09)
        override val ButtonContrast = Color(0xFF32CD32)
    }

    // Purple Theme
    object Purple : ThemeColors() {
        override val Primary = Color(0xFF9C27B0)
        override val Secondary = Color(0xFF8E24AA)
        override val Tertiary = Color(0xFF4A148C)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFE1BEE7)
        override val SecondaryContainer = Color(0xFFCE93D8)
        override val TertiaryContainer = Color(0xFFB39DDB)
        override val OnPrimaryContainer = Color(0xFF1F0A23)
        override val OnSecondaryContainer = Color(0xFF1C0A21)
        override val OnTertiaryContainer = Color(0xFF12071C)
        override val ButtonContrast = Color(0xFFDA70D6)
    }

    // Orange Theme
    object Orange : ThemeColors() {
        override val Primary = Color(0xFFFF9800)
        override val Secondary = Color(0xFFFB8C00)
        override val Tertiary = Color(0xFFE65100)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFFFE0B2)
        override val SecondaryContainer = Color(0xFFFFCC80)
        override val TertiaryContainer = Color(0xFFFFB74D)
        override val OnPrimaryContainer = Color(0xFF1A1100)
        override val OnSecondaryContainer = Color(0xFF1A1000)
        override val OnTertiaryContainer = Color(0xFF1A0B00)
        override val ButtonContrast = Color(0xFFFF6347)
    }

    // Pink Theme
    object Pink : ThemeColors() {
        override val Primary = Color(0xFFE91E63)
        override val Secondary = Color(0xFFD81B60)
        override val Tertiary = Color(0xFF880E4F)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFF8BBD0)
        override val SecondaryContainer = Color(0xFFF48FB1)
        override val TertiaryContainer = Color(0xFFE91E63)
        override val OnPrimaryContainer = Color(0xFF2E0A14)
        override val OnSecondaryContainer = Color(0xFF2B0A13)
        override val OnTertiaryContainer = Color(0xFF1C0311)
        override val ButtonContrast = Color(0xFFFF1493)
    }

    // Gray Theme
    object Gray : ThemeColors() {
        override val Primary = Color(0xFF9E9E9E)
        override val Secondary = Color(0xFF757575)
        override val Tertiary = Color(0xFF616161)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFEEEEEE)
        override val SecondaryContainer = Color(0xFFE0E0E0)
        override val TertiaryContainer = Color(0xFFBDBDBD)
        override val OnPrimaryContainer = Color(0xFF1A1A1A)
        override val OnSecondaryContainer = Color(0xFF171717)
        override val OnTertiaryContainer = Color(0xFF141414)
        override val ButtonContrast = Color(0xFF696969)
    }

    object Yellow : ThemeColors() {
        override val Primary = Color(0xFFFFD700)
        override val Secondary = Color(0xFFFFBC52)
        override val Tertiary = Color(0xFF795548)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFFFF7D6)
        override val SecondaryContainer = Color(0xFFFFE6B3)
        override val TertiaryContainer = Color(0xFFD7CCC8)
        override val OnPrimaryContainer = Color(0xFF1A1600)
        override val OnSecondaryContainer = Color(0xFF1A1100)
        override val OnTertiaryContainer = Color(0xFF1A1717)
        override val ButtonContrast = Color(0xFFFFD700)
    }

    companion object {
        fun fromName(name: String): ThemeColors = when (name.lowercase()) {
            "blue" -> Blue
            "green" -> Green
            "purple" -> Purple
            "orange" -> Orange
            "pink" -> Pink
            "gray" -> Gray
            "white" -> Yellow
            else -> Default
        }
    }
}