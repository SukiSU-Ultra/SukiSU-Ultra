package com.sukisu.ultra.ui.theme

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

    // 表面颜色
    abstract val Surface: Color
    abstract val SurfaceVariant: Color
    abstract val OnSurface: Color
    abstract val OnSurfaceVariant: Color

    // 错误状态颜色
    abstract val Error: Color
    abstract val OnError: Color
    abstract val ErrorContainer: Color
    abstract val OnErrorContainer: Color

    // 边框和背景色
    abstract val Outline: Color
    abstract val OutlineVariant: Color
    abstract val Background: Color
    abstract val OnBackground: Color

    // 默认主题 (白色)
    object Default : ThemeColors() {
        override val Primary = Color(0xFFFFFFFF)
        override val Secondary = Color(0xFF5F6368)
        override val Tertiary = Color(0xFFFFFFFF)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFD1E3FF)
        override val SecondaryContainer = Color(0xFFE4E6E8)
        override val TertiaryContainer = Color(0xFFD0E1FC)
        override val OnPrimaryContainer = Color(0xFF0D2E5E)
        override val OnSecondaryContainer = Color(0xFF24262A)
        override val OnTertiaryContainer = Color(0xFF0A2E62)
        override val ButtonContrast = Color(0xFF0A2E62)

        override val Surface = Color(0xFFFCFCFC)
        override val SurfaceVariant = Color(0xFFF2F2F2)
        override val OnSurface = Color(0xFF202124)
        override val OnSurfaceVariant = Color(0xFF5F6368)

        override val Error = Color(0xFFD93025)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFDECEA)
        override val OnErrorContainer = Color(0xFF58160F)

        override val Outline = Color(0xFFDADADA)
        override val OutlineVariant = Color(0xFFEEEEEE)
        override val Background = Color(0xFFFFFFFF)
        override val OnBackground = Color(0xFF202124)
    }

    // 蓝色主题
    object Blue : ThemeColors() {
        override val Primary = Color(0xFF2196F3)
        override val Secondary = Color(0xFF64B5F6)
        override val Tertiary = Color(0xFF0D47A1)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFD6EAFF)
        override val SecondaryContainer = Color(0xFFE3F2FD)
        override val TertiaryContainer = Color(0xFFCFD8DC)
        override val OnPrimaryContainer = Color(0xFF0A3049)
        override val OnSecondaryContainer = Color(0xFF0D3C61)
        override val OnTertiaryContainer = Color(0xFF071D41)
        override val ButtonContrast = Color(0xFF1976D2)

        override val Surface = Color(0xFFF5F9FF)
        override val SurfaceVariant = Color(0xFFEDF5FE)
        override val OnSurface = Color(0xFF1A1C1E)
        override val OnSurfaceVariant = Color(0xFF42474E)

        override val Error = Color(0xFFB00020)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFDE7E9)
        override val OnErrorContainer = Color(0xFF410008)

        override val Outline = Color(0xFFBAC3CF)
        override val OutlineVariant = Color(0xFFDFE3EB)
        override val Background = Color(0xFFFAFCFF)
        override val OnBackground = Color(0xFF1A1C1E)
    }

    // 绿色主题
    object Green : ThemeColors() {
        override val Primary = Color(0xFF43A047)
        override val Secondary = Color(0xFF66BB6A)
        override val Tertiary = Color(0xFF1B5E20)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFD8EFDB)
        override val SecondaryContainer = Color(0xFFE8F5E9)
        override val TertiaryContainer = Color(0xFFB9F6CA)
        override val OnPrimaryContainer = Color(0xFF0A280D)
        override val OnSecondaryContainer = Color(0xFF0E2912)
        override val OnTertiaryContainer = Color(0xFF051B07)
        override val ButtonContrast = Color(0xFF2E7D32)

        override val Surface = Color(0xFFF6FBF6)
        override val SurfaceVariant = Color(0xFFEDF7EE)
        override val OnSurface = Color(0xFF191C19)
        override val OnSurfaceVariant = Color(0xFF414941)

        override val Error = Color(0xFFC62828)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFF8D7DA)
        override val OnErrorContainer = Color(0xFF4A0808)

        override val Outline = Color(0xFFBDC9BF)
        override val OutlineVariant = Color(0xFFDDE6DE)
        override val Background = Color(0xFFFBFDFB)
        override val OnBackground = Color(0xFF191C19)
    }

    // 紫色主题
    object Purple : ThemeColors() {
        override val Primary = Color(0xFF9C27B0)
        override val Secondary = Color(0xFFBA68C8)
        override val Tertiary = Color(0xFF6A1B9A)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFF3D8F8)
        override val SecondaryContainer = Color(0xFFF5E9F7)
        override val TertiaryContainer = Color(0xFFE1BEE7)
        override val OnPrimaryContainer = Color(0xFF2A0934)
        override val OnSecondaryContainer = Color(0xFF3C0F50)
        override val OnTertiaryContainer = Color(0xFF1D0830)
        override val ButtonContrast = Color(0xFF8E24AA)

        override val Surface = Color(0xFFFCF6FF)
        override val SurfaceVariant = Color(0xFFF5EEFA)
        override val OnSurface = Color(0xFF1D1B1E)
        override val OnSurfaceVariant = Color(0xFF49454E)

        override val Error = Color(0xFFD50000)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFFDCD5)
        override val OnErrorContainer = Color(0xFF480000)

        override val Outline = Color(0xFFC9B9D0)
        override val OutlineVariant = Color(0xFFE8DAED)
        override val Background = Color(0xFFFFFBFF)
        override val OnBackground = Color(0xFF1D1B1E)
    }

    // 橙色主题
    object Orange : ThemeColors() {
        override val Primary = Color(0xFFFF9800)
        override val Secondary = Color(0xFFFFB74D)
        override val Tertiary = Color(0xFFE65100)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFF000000)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFFFECCC)
        override val SecondaryContainer = Color(0xFFFFF0D9)
        override val TertiaryContainer = Color(0xFFFFD180)
        override val OnPrimaryContainer = Color(0xFF351F00)
        override val OnSecondaryContainer = Color(0xFF3D2800)
        override val OnTertiaryContainer = Color(0xFF2E1500)
        override val ButtonContrast = Color(0xFFEF6C00)

        override val Surface = Color(0xFFFFF8F3)
        override val SurfaceVariant = Color(0xFFFFF0E6)
        override val OnSurface = Color(0xFF1F1B16)
        override val OnSurfaceVariant = Color(0xFF4E4639)

        override val Error = Color(0xFFD32F2F)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFFDBC8)
        override val OnErrorContainer = Color(0xFF490700)

        override val Outline = Color(0xFFD6C3AD)
        override val OutlineVariant = Color(0xFFEFDFCC)
        override val Background = Color(0xFFFFFBFF)
        override val OnBackground = Color(0xFF1F1B16)
    }

    // 粉色主题
    object Pink : ThemeColors() {
        override val Primary = Color(0xFFE91E63)
        override val Secondary = Color(0xFFF06292)
        override val Tertiary = Color(0xFF880E4F)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFFCE4EC)
        override val SecondaryContainer = Color(0xFFFCE4EC)
        override val TertiaryContainer = Color(0xFFF8BBD0)
        override val OnPrimaryContainer = Color(0xFF3B0819)
        override val OnSecondaryContainer = Color(0xFF3B0819)
        override val OnTertiaryContainer = Color(0xFF2B0516)
        override val ButtonContrast = Color(0xFFD81B60)

        override val Surface = Color(0xFFFFF7F9)
        override val SurfaceVariant = Color(0xFFFCEEF2)
        override val OnSurface = Color(0xFF201A1C)
        override val OnSurfaceVariant = Color(0xFF534347)

        override val Error = Color(0xFFB71C1C)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFFDAD6)
        override val OnErrorContainer = Color(0xFF410002)

        override val Outline = Color(0xFFD6BABF)
        override val OutlineVariant = Color(0xFFEFDDE0)
        override val Background = Color(0xFFFFFBFF)
        override val OnBackground = Color(0xFF201A1C)
    }

    // 灰色主题
    object Gray : ThemeColors() {
        override val Primary = Color(0xFF607D8B)
        override val Secondary = Color(0xFF90A4AE)
        override val Tertiary = Color(0xFF455A64)
        override val OnPrimary = Color(0xFFFFFFFF)
        override val OnSecondary = Color(0xFFFFFFFF)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFECEFF1)
        override val SecondaryContainer = Color(0xFFECEFF1)
        override val TertiaryContainer = Color(0xFFCFD8DC)
        override val OnPrimaryContainer = Color(0xFF1A2327)
        override val OnSecondaryContainer = Color(0xFF1A2327)
        override val OnTertiaryContainer = Color(0xFF121A1D)
        override val ButtonContrast = Color(0xFF546E7A)

        override val Surface = Color(0xFFF6F9FB)
        override val SurfaceVariant = Color(0xFFEEF2F4)
        override val OnSurface = Color(0xFF191C1E)
        override val OnSurfaceVariant = Color(0xFF41484D)

        override val Error = Color(0xFFC62828)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFFDAD6)
        override val OnErrorContainer = Color(0xFF410002)

        override val Outline = Color(0xFFBDC1C4)
        override val OutlineVariant = Color(0xFFDDE1E3)
        override val Background = Color(0xFFFBFCFE)
        override val OnBackground = Color(0xFF191C1E)
    }

    // 黄色主题
    object Yellow : ThemeColors() {
        override val Primary = Color(0xFFFFC107)
        override val Secondary = Color(0xFFFFD54F)
        override val Tertiary = Color(0xFFFF8F00)
        override val OnPrimary = Color(0xFF000000)
        override val OnSecondary = Color(0xFF000000)
        override val OnTertiary = Color(0xFFFFFFFF)
        override val PrimaryContainer = Color(0xFFFFF8E1)
        override val SecondaryContainer = Color(0xFFFFF8E1)
        override val TertiaryContainer = Color(0xFFFFECB3)
        override val OnPrimaryContainer = Color(0xFF332A00)
        override val OnSecondaryContainer = Color(0xFF332A00)
        override val OnTertiaryContainer = Color(0xFF221200)
        override val ButtonContrast = Color(0xFFFFB300)

        override val Surface = Color(0xFFFFFAF3)
        override val SurfaceVariant = Color(0xFFFFF7E6)
        override val OnSurface = Color(0xFF1F1C17)
        override val OnSurfaceVariant = Color(0xFF4E4A3C)

        override val Error = Color(0xFFB71C1C)
        override val OnError = Color(0xFFFFFFFF)
        override val ErrorContainer = Color(0xFFFFDAD6)
        override val OnErrorContainer = Color(0xFF410002)

        override val Outline = Color(0xFFD1C8AF)
        override val OutlineVariant = Color(0xFFEEE8D7)
        override val Background = Color(0xFFFFFCF8)
        override val OnBackground = Color(0xFF1F1C17)
    }

    companion object {
        fun fromName(name: String): ThemeColors = when (name.lowercase()) {
            "blue" -> Blue
            "green" -> Green
            "purple" -> Purple
            "orange" -> Orange
            "pink" -> Pink
            "gray" -> Gray
            "yellow" -> Yellow
            else -> Default
        }
    }
}