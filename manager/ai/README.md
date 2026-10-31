# AI assistant library (`:ai`)

Optional Android library (AAR) containing the AI assistant: provider protocols
(OpenAI-compatible, Ollama, Anthropic), streaming and tool-call parsing, the tool
registry and permission scopes, chat settings/history, Markdown rendering, and
the Material 3 / Miuix chat, settings and home-card UIs.

Compose/Kotlin UI cannot be compiled into a native `.so`; the Android binary
unit for this feature is an AAR. It can be dropped in or removed as a whole, and
the host hides every AI entry when it is absent.

## Optional deployment

Two modules make the feature optional:

- `:ai-api` — small, always-present bridge. It contains only the host SPI, the
  UI provider interface, shared data types, the GitHub release URL validator and
  two host-side strings. It has no AI implementation.
- `:ai` — the full assistant, built as a normal AAR. It is loaded by name:
  `com.sukisu.ultra.ai.AiFeatureProviderImpl` via
  `com.sukisu.ultra.ai.api.AiFeatureBridge`.

Ways to include it:

```bash
# keep the module in the build (default)
./gradlew :app:assembleDebug

# disable the module entirely
./gradlew -Pai=false :app:assembleDebug
```

```kotlin
// app/build.gradle.kts (already wired): a drop-in AAR wins over the module
// app/libs/ai.aar -> included when present
```

Without `:ai` (and without `app/libs/ai.aar`), the host still compiles and
`AiFeatureBridge.isAvailable` is `false`. The home card, the appearance switch
and the AI navigation entries are not rendered.

Build the AAR with `./gradlew :ai:assembleRelease`
(`ai/build/outputs/aar/ai-release.aar`). The AAR requires `:ai-api` at runtime;
do not exclude the bridge module when using the AAR.

## Host integration

1. Add `:ai-api` (always) and optionally `:ai`/the AAR (see above).
2. Implement the `AiHost` services from `com.sukisu.ultra.ai.api`:
   - `AiEnvironmentService` – manager/device snapshot JSON
   - `AiThemeService` – appearance read/write and theme package export
   - `AiExtensionsService` – extension/KPM/SuSFS/umount/dynamic-manager tools
   - `AiSuperuserService` – app root and temporary-root tools
   - `AiModuleService` – installed modules and registry/GitHub installs
   - `AiFeatureService` – page catalogue and host-defined navigation targets
   - `AiThemeImageService` – background/home-card storage and sharing
   - `executeRootShell` – user-confirmed shell blocks
3. Install the host once; it is ignored when the AI library is absent:
   ```kotlin
   class MyApplication : Application() {
       override fun onCreate() {
           super.onCreate()
           if (AiFeatureBridge.isAvailable) {
               AiFeatureBridge.install(MyHost(this))
           }
       }
   }
   ```
4. Render the optional UI through the bridge, not the library classes:
   ```kotlin
   if (AiFeatureBridge.isAvailable) {
       AiFeatureBridge.HomeCardMaterial(onOpenChat = { /* push chat */ })
   }

   AiFeatureBridge.ChatScreen(
       uiMode = AiUiMode.Material, // or AiUiMode.Miuix
       onClose = { navigator.pop() },
       onOpenSettings = { navigator.push(AiSettingsRoute) },
       onNavigate = { target -> /* handle your host-defined target */ },
   )
   AiFeatureBridge.SettingsScreen(uiMode = AiUiMode.Material, onBack = { navigator.pop() })
   ```
   `AiNavigationTarget` is an opaque marker; the library never interprets it.
   `AiFeatureService` returns host objects and the app maps them to its routes.

The library manifest declares the network permissions used by remote and LAN
providers. Applications that allow plain-HTTP local inference servers also need
a cleartext-enabled network security config (`network_security_config.xml`).

## Layout

`ai-api`:
- `AiHost.kt` – host SPI, shared models, `AiUiMode`
- `AiFeatureProvider.kt` – provider interface and `AiFeatureBridge`
- `AiGithubUrls.kt` – shared release URL validation
- `res/` – the two strings used by the host-side appearance switch

`ai`:
- `AiAssistant` / `AiFeatureProviderImpl` – runtime entry and reflective provider
- `AiApi.kt` – provider protocols, streaming, model discovery
- `AiTools.kt` – tool schemas, scope checks and dispatch
- `AiImageController.kt` – image generation/editing; storage is host-side
- `AiChat*`, `AiHomeCard*`, `AiSettings*` – UI
- `AiUiKit.kt` – theme-aware Material/Miuix widgets used by the assistant
- `src/main/res` – AI strings (English + zh-rCN)
- `src/test` – provider parsing, config, Markdown, permissions, web parsing

The SukiSU-specific tool backends and `ManagerAiHost` live in
`app/src/main/java/com/sukisu/ultra/ai/host`; they implement only the `:ai-api`
interfaces, so they compile and remain inert when the AAR is absent.
