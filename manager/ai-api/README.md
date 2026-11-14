# `:ai-api` — optional assistant bridge

This module is the small, always-present integration surface for the optional AI
assistant. It contains no assistant implementation: only the host SPI,
shared models, the GitHub release URL validator and the host-side strings for
the appearance switch.

The full assistant is a separate AAR (`:ai` in the `ai_chat` branch):

- `AiFeatureBridge` loads `com.sukisu.ultra.ai.AiFeatureProviderImpl` by name.
- When the AAR is absent, `AiFeatureBridge.isAvailable` is `false` and every
  bridge UI call is a no-op.
- The host adapter in `app/.../ai/host` implements `AiHost` from this module and
  compiles whether or not the AAR is present.

## Enabling the feature

Either add the `:ai` Gradle module to `settings.gradle.kts`, or drop a prebuilt
AAR at `app/libs/ai.aar`. `app/build.gradle.kts` prefers the AAR when present.
Without either, the home card, the appearance switch and the AI routes stay
hidden.

Keep this module in the build when using the AAR; the AAR does not bundle these
interface classes.
