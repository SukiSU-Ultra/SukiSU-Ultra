package com.sukisu.ultra.data.repository

/**
 * Built-in default theme source.
 *
 * The token is intentionally shipped with the app so a fresh install can open
 * the official mirror without asking the user to copy a secret. It is a shared
 * gate, not a per-user credential: it can be extracted from the APK. Rotating
 * it on the server requires updating this value or setting a custom token in
 * the manager.
 */
object ThemeStoreDefaults {
    const val BASE_URL = "https://themes.neko.shirkneko.top:8443/"
    const val TOKEN = "80791959008c80bc4ceee61ae66bbab6877192394a3f76498259992bc1cebb1e"
}
