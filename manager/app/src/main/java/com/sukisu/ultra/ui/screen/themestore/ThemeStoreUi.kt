package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R

/** Localized display label for a mirror source, used by account pickers and aggregated rows. */
@Composable
internal fun ThemeStoreSource.displayName(): String =
    if (isDefault) {
        stringResource(R.string.theme_store_default_source)
    } else {
        name.ifBlank {
            baseUrl.removePrefix("https://").removePrefix("http://").removeSuffix("/")
        }
    }
