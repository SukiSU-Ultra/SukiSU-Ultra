-verbose
-optimizationpasses 5

-dontwarn org.conscrypt.**
-dontwarn kotlinx.serialization.**

# MMRL:webui reflection
-keep class androidx.compose.ui.graphics.Color { *; }
-keep class androidx.compose.material3.ButtonColors { *; }
-keep class androidx.compose.material3.CardColors { *; }
-keep class androidx.compose.material3.ColorScheme { *; }
-keep class com.dergoogler.mmrl.platform.model.ModId { *; }
-keep class com.dergoogler.mmrl.webui.interfaces.WXOptions { *; }
-keep class com.dergoogler.mmrl.webui.interfaces.WXInterface { *; }
-keep class com.dergoogler.mmrl.webui.interfaces.** { *; }
-keep class com.sukisu.ultra.ui.webui.WebViewInterface { *; }

-keep,allowobfuscation class * extends com.dergoogler.mmrl.platform.content.IService { *; }