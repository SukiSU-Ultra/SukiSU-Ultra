# Keep kotlinx.serialization generated serializers for persisted AI state.
-keepclassmembers class **$* implements kotlinx.serialization.KSerializer { *; }

# Loaded by name from the host through AiFeatureBridge.
-keep class com.sukisu.ultra.ai.AiFeatureProviderImpl { *; }
