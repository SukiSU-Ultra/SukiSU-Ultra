# Merging the AI assistant into `main`

The current `main` tree only needs the bridge and the host adapter to compile.
The full assistant can then be added either as the `:ai` module or as a
prebuilt AAR. Without it, `AiFeatureBridge.isAvailable` is false and all AI
entries are hidden.

## 1. Always merge (integration surface)

### New module

- `manager/ai-api/` — whole directory (host SPI, `AiFeatureBridge`,
  `AiFeatureProvider`, shared models, two host-side strings)

### Host adapter (app)

- `manager/app/src/main/java/com/sukisu/ultra/ai/host/` — whole directory:
  - `ManagerAiHost.kt`, `AiModuleServiceHost.kt`
  - `AiEnvironment.kt`, `AiThemeController.kt`, `AiThemeImageStore.kt`
  - `AiExtensionsController.kt`, `AiSuperuserController.kt`
  - `AiModuleController.kt`, `AiManagerData.kt`, `AiSusfsController.kt`
  - `AiFeatureCatalog.kt`

### Build files

- `manager/settings.gradle.kts` — `include(":ai-api")` plus the optional `:ai`
  switch (`-Pai=false`)
- `manager/build.gradle.kts` — `agp-library` plugin declaration
- `manager/gradle/libs.versions.toml` — `agp-library`, `androidx-core-ktx`
- `manager/app/build.gradle.kts` — `:ai-api`; optional `app/libs/ai.aar` or
  `:ai` module

### App lifecycle and navigation

- `KernelSUApplication.kt` — install the host only when the bridge is available
- `ui/MainActivity.kt` — AI routes through `AiFeatureBridge`, target mapping,
  pager page-request effect
- `ui/navigation3/Navigator.kt` — `navigateTo`
- `ui/navigation3/Routes.kt` — `AiAssistant`, `AiSettings`, sectioned
  `ColorPalette`/`SuSFS`
- `ui/viewmodel/MainActivityViewModel.kt` — `openMainPage`, `MainPageRequest`

### Home entry and appearance switch

- `ui/screen/home/HomeMaterial.kt`
- `ui/screen/home/HomeMiuix.kt`
- `ui/screen/home/HomeScreen.kt`
- `ui/screen/home/HomeUiState.kt`
- `ui/viewmodel/HomeViewModel.kt`
- `data/repository/SettingsRepository.kt`
- `data/repository/SettingsRepositoryImpl.kt`
- `ui/screen/colorpalette/ColorPaletteScreen.kt`
- `ui/screen/colorpalette/ColorPaletteScreenMaterial.kt`
- `ui/screen/colorpalette/ColorPaletteScreenMiuix.kt`
- `ui/screen/colorpalette/ColorPaletteUiState.kt`
- `ui/viewmodel/SettingsViewModel.kt`
- `ui/screen/settings/SettingsUiState.kt`

### Deep-link / tool support

- `ui/screen/settings/SettingsSection.kt` (new)
- `ui/screen/settings/SettingsMaterial.kt` (section anchors)
- `ui/screen/settings/SettingsMiuix.kt` (section anchors)
- `ui/screen/settings/SettingsScreen.kt` (section request wiring)
- `ui/screen/susfs/SuSFSScreen.kt` and `SuSFSUiState.kt` (tab deep links)
- `ui/screen/appprofile/AppProfileScreen.kt` (uid deep link resolution)
- `ui/screen/extensions/ExtensionCatalog.kt` (sectioned `SuSFS` route)
- `ui/screen/kpm/KpmOperations.kt` (KPM install/uninstall used by tools)
- `ui/util/KsuCli.kt` (quoting used by root tools)
- `ui/util/ThemePackageStorage.kt` (theme package export with images)

### Platform config

- `app/src/main/AndroidManifest.xml` — LAN/loopback permissions
- `app/src/main/res/xml/network_security_config.xml` — cleartext for local
  inference servers

### Recommended test

- `app/src/test/java/com/sukisu/ultra/ui/screen/settings/SettingsSectionTest.kt`

## 2. Optional full assistant (pick one)

### Option A — merge the source module

- `manager/ai/` — whole directory (UI, API protocols, tools, resources, tests)

This keeps `:ai` in the Gradle build and the default project dependency works.

### Option B — merge only the binary

- Build `manager/ai/build/outputs/aar/ai-release.aar`
- Copy it to `manager/app/libs/ai.aar`
- Do **not** merge `manager/ai/`; run with `-Pai=false` or leave it out of
  `settings.gradle.kts`

`app/build.gradle.kts` prefers `app/libs/ai.aar` when present.

The AAR still requires `:ai-api` at runtime; do not exclude the bridge module.

## 3. Do not merge

- `kernel/Kbuild` — the `REPO_BRANCH := ai_chat` change is unrelated to the
  feature.
- `app/src/main/java/com/sukisu/ultra/ui/screen/ai/` — the old monolithic
  location; all code now lives in `:ai` (or the AAR).
- AI strings in `app/src/main/res/values*/strings.xml` — they live in the AAR;
  only the two appearance-switch strings live in `:ai-api`.
- `app/lint.xml` — the AI translation ignore now lives in `:ai`/`:ai-api`.

## Verification

```bash
# Integration only (no assistant code)
./gradlew -Pai=false :app:compileDebugKotlin

# With the source module
./gradlew :ai:testDebugUnitTest :app:assembleDebug

# With the binary
cp ai/build/outputs/aar/ai-release.aar app/libs/ai.aar
./gradlew -Pai=false :app:assembleDebug
```

When the assistant is absent, the host still compiles and the home card, the
appearance switch and the AI routes are not shown.
