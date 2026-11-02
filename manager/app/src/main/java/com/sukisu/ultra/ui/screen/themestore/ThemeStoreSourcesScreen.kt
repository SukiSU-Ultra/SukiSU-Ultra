package com.sukisu.ultra.ui.screen.themestore

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.IconButton as MaterialIconButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.ThemeStoreSourceConfig
import com.sukisu.ultra.data.repository.ThemeStoreDefaults
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import kotlinx.serialization.json.Json
import kotlinx.coroutines.launch
import java.util.UUID

internal const val THEME_SOURCES_RESULT_KEY = "theme_store_sources_changed"

private val ThemeStoreSourceListSaver = listSaver(
    save = { sources ->
        sources.map { source ->
            Json.encodeToString(ThemeStoreSourceConfig.serializer(), source)
        }
    },
    restore = { values ->
        values.mapNotNull { value ->
            runCatching {
                Json.decodeFromString(ThemeStoreSourceConfig.serializer(), value)
            }.getOrNull()
        }
    },
)

private sealed interface SourceTestState {
    data object Testing : SourceTestState
    data class Success(val themes: Int, val cached: Boolean) : SourceTestState
    data class Failure(val message: String) : SourceTestState
}

private data class SourceEndpoints(
    val catalog: String,
    val themes: String,
    val previews: String,
    val avatars: String,
    val health: String,
    val tokenHeader: String,
)

@Composable
fun ThemeStoreSourcesScreen(
    settingsViewModel: SettingsViewModel = viewModel(),
) {
    val settings by settingsViewModel.uiState.collectAsStateWithLifecycle()
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repository = remember(context) { ThemeStoreRepository(context) }
    val builtInBase = remember {
        ThemeStoreRepository.normalizeBaseUrl(ThemeStoreDefaults.BASE_URL) ?: ThemeStoreDefaults.BASE_URL
    }

    var defaultBase by rememberSaveable(settings.themeStoreBaseUrl) {
        mutableStateOf(settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL })
    }
    var defaultToken by rememberSaveable(settings.themeStoreToken) {
        mutableStateOf(settings.themeStoreToken)
    }
    var showBuiltInToken by rememberSaveable { mutableStateOf(false) }
    var extraSources by rememberSaveable(
        settings.themeStoreExtraSources,
        stateSaver = ThemeStoreSourceListSaver,
    ) {
        mutableStateOf(settings.themeStoreExtraSources)
    }
    var tests by remember { mutableStateOf<Map<String, SourceTestState>>(emptyMap()) }
    var showSaveError by remember { mutableStateOf(false) }

    val normalizedDefault = ThemeStoreRepository.normalizeBaseUrl(
        defaultBase.ifBlank { ThemeStoreDefaults.BASE_URL },
    )
    val isBuiltIn = normalizedDefault == builtInBase
    val showDefaultToken = showBuiltInToken || !isBuiltIn || defaultToken.isNotBlank()
    val effectiveDefaultBase = defaultBase.ifBlank { ThemeStoreDefaults.BASE_URL }
    val defaultEndpoints = endpointsFor(effectiveDefaultBase)
    val effectiveDefaultToken = defaultToken.trim().ifBlank {
        if (isBuiltIn) ThemeStoreDefaults.TOKEN else ""
    }

    fun updateExtra(index: Int, source: ThemeStoreSourceConfig) {
        extraSources = extraSources.toMutableList().also { it[index] = source }
        tests = tests - extraTestKey(source)
        showSaveError = false
    }

    fun removeExtra(index: Int) {
        val source = extraSources.getOrNull(index)
        extraSources = extraSources.toMutableList().also { it.removeAt(index) }
        if (source != null) tests = tests - extraTestKey(source)
        showSaveError = false
    }

    @SuppressLint("LocalContextGetResourceValueCall")
    fun testSource(key: String, baseUrl: String, token: String) {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl)
        if (normalized == null) {
            tests = tests + (key to SourceTestState.Failure(
                context.getString(R.string.theme_store_source_invalid),
            ))
            return
        }
        tests = tests + (key to SourceTestState.Testing)
        scope.launch {
            val result = repository.loadCatalog(normalized, token)
            tests = tests + (
                key to result.fold(
                    onSuccess = { SourceTestState.Success(it.catalog.themes.size, it.fromCache) },
                    onFailure = {
                        SourceTestState.Failure(
                            it.message?.takeIf { message -> message.isNotBlank() }
                                ?: context.getString(R.string.theme_store_source_test_failed),
                        )
                    },
                )
            )
        }
    }

    fun save() {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(
            defaultBase.ifBlank { ThemeStoreDefaults.BASE_URL },
        ) ?: run {
            showSaveError = true
            return
        }
        val extrasInvalid = extraSources.any { source ->
            source.baseUrl.isNotBlank() &&
                ThemeStoreRepository.normalizeBaseUrl(source.baseUrl) == null
        }
        if (extrasInvalid) {
            showSaveError = true
            return
        }
        val cleaned = extraSources
            .filter { it.baseUrl.isNotBlank() }
            .map { source ->
                source.copy(
                    name = source.name.trim(),
                    baseUrl = ThemeStoreRepository.normalizeBaseUrl(source.baseUrl).orEmpty(),
                    token = source.token.trim(),
                    adminUrl = "",
                )
            }
            .distinctBy { it.baseUrl }
        settingsViewModel.setThemeStoreBaseUrl(normalized)
        settingsViewModel.setThemeStoreToken(defaultToken.trim())
        settingsViewModel.setThemeStoreAdminUrl("")
        settingsViewModel.setThemeStoreExtraSources(cleaned)
        navigator.setResult(THEME_SOURCES_RESULT_KEY, true)
    }

    ThemeStoreSourcesMaterial(
        defaultBase = defaultBase,
        onDefaultBaseChange = {
            defaultBase = it
            tests = tests - "default"
            showSaveError = false
        },
        defaultToken = defaultToken,
        onDefaultTokenChange = {
            defaultToken = it
            tests = tests - "default"
            showSaveError = false
        },
        showDefaultToken = showDefaultToken,
        onShowToken = { showBuiltInToken = true },
        isBuiltIn = isBuiltIn,
        defaultEndpoints = defaultEndpoints,
        defaultTest = tests["default"],
        onTestDefault = { testSource("default", effectiveDefaultBase, effectiveDefaultToken) },
        extraSources = extraSources,
        onUpdateExtra = ::updateExtra,
        onRemoveExtra = ::removeExtra,
        onAddExtra = {
            extraSources = extraSources + ThemeStoreSourceConfig(id = UUID.randomUUID().toString())
        },
        tests = tests,
        onTestExtra = { source ->
            testSource(extraTestKey(source), source.baseUrl, source.token)
        },
        showSaveError = showSaveError,
        onSave = ::save,
        onBack = { navigator.pop() },
    )
}

@Composable
private fun ThemeStoreSourcesMaterial(
    defaultBase: String,
    onDefaultBaseChange: (String) -> Unit,
    defaultToken: String,
    onDefaultTokenChange: (String) -> Unit,
    showDefaultToken: Boolean,
    onShowToken: () -> Unit,
    isBuiltIn: Boolean,
    defaultEndpoints: SourceEndpoints?,
    defaultTest: SourceTestState?,
    onTestDefault: () -> Unit,
    extraSources: List<ThemeStoreSourceConfig>,
    onUpdateExtra: (Int, ThemeStoreSourceConfig) -> Unit,
    onRemoveExtra: (Int) -> Unit,
    onAddExtra: () -> Unit,
    tests: Map<String, SourceTestState>,
    onTestExtra: (ThemeStoreSourceConfig) -> Unit,
    showSaveError: Boolean,
    onSave: () -> Unit,
    onBack: () -> Unit,
) {
    ExpressiveScaffold(
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
        topBar = {
            TopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = {
                    MaterialText(
                        text = stringResource(R.string.theme_store_sources),
                        style = MaterialTheme.typography.titleLarge,
                    )
                },
                actions = {
                    MaterialTextButton(onClick = onSave) {
                        MaterialText(stringResource(R.string.theme_store_save))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                    scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                ),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 13.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "summary") {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                    ),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        MaterialText(
                            text = stringResource(R.string.theme_store_sources_summary),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        MaterialText(
                            text = stringResource(R.string.theme_store_upload_default_only),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }
            if (showSaveError) {
                item(key = "save-error") {
                    MaterialText(
                        text = stringResource(R.string.theme_store_save_invalid),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            item(key = "default") {
                SourceCardMaterial(
                    title = stringResource(R.string.theme_store_default_source),
                    subtitle = stringResource(R.string.theme_store_capability_upload),
                    baseUrl = defaultBase,
                    onBaseUrlChange = onDefaultBaseChange,
                    token = defaultToken,
                    onTokenChange = onDefaultTokenChange,
                    showToken = showDefaultToken,
                    onShowToken = onShowToken,
                    isBuiltIn = isBuiltIn,
                    endpoints = defaultEndpoints,
                    test = defaultTest,
                    onTest = onTestDefault,
                )
            }
            if (extraSources.isNotEmpty()) {
                item(key = "extra-title") {
                    MaterialText(
                        text = stringResource(R.string.theme_store_extra_sources),
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(start = 4.dp, top = 6.dp),
                    )
                }
            }
            itemsIndexed(extraSources, key = { index, source -> source.id.ifBlank { "extra-$index" } }) { index, source ->
                SourceCardMaterial(
                    title = source.name.ifBlank { stringResource(R.string.theme_store_source_unnamed) },
                    subtitle = stringResource(R.string.theme_store_capability_read),
                    baseUrl = source.baseUrl,
                    onBaseUrlChange = { onUpdateExtra(index, source.copy(baseUrl = it)) },
                    token = source.token,
                    onTokenChange = { onUpdateExtra(index, source.copy(token = it)) },
                    showToken = true,
                    onShowToken = null,
                    isBuiltIn = false,
                    endpoints = endpointsFor(source.baseUrl),
                    test = tests[extraTestKey(source)],
                    onTest = { onTestExtra(source) },
                    name = source.name,
                    onNameChange = { onUpdateExtra(index, source.copy(name = it)) },
                    onRemove = { onRemoveExtra(index) },
                )
            }
            item(key = "add") {
                MaterialTextButton(
                    onClick = onAddExtra,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    MaterialIcon(
                        imageVector = Icons.Rounded.Add,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.size(4.dp))
                    MaterialText(stringResource(R.string.theme_store_add_source))
                }
            }
            item(key = "bottom-inset") {
                Spacer(
                    Modifier.height(
                        WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 20.dp,
                    ),
                )
            }
        }
    }
}

@Composable
private fun SourceCardMaterial(
    title: String,
    subtitle: String,
    baseUrl: String,
    onBaseUrlChange: (String) -> Unit,
    token: String,
    onTokenChange: (String) -> Unit,
    showToken: Boolean,
    onShowToken: (() -> Unit)?,
    isBuiltIn: Boolean,
    endpoints: SourceEndpoints?,
    test: SourceTestState?,
    onTest: () -> Unit,
    name: String? = null,
    onNameChange: ((String) -> Unit)? = null,
    onRemove: (() -> Unit)? = null,
) {
    var endpointsExpanded by rememberSaveable { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    MaterialText(text = title, style = MaterialTheme.typography.titleMedium)
                    MaterialText(
                        text = subtitle,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (onRemove != null) {
                    MaterialIconButton(onClick = onRemove) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.Delete,
                            contentDescription = stringResource(R.string.theme_store_remove_source),
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
            if (name != null && onNameChange != null) {
                OutlinedTextField(
                    value = name,
                    onValueChange = onNameChange,
                    label = { MaterialText(stringResource(R.string.theme_store_source_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            OutlinedTextField(
                value = baseUrl,
                onValueChange = onBaseUrlChange,
                label = { MaterialText(stringResource(R.string.theme_store_url)) },
                singleLine = true,
                supportingText = {
                    MaterialText(stringResource(R.string.theme_store_url_hint))
                },
                modifier = Modifier.fillMaxWidth(),
            )
            if (showToken) {
                OutlinedTextField(
                    value = token,
                    onValueChange = onTokenChange,
                    label = { MaterialText(stringResource(R.string.theme_store_token)) },
                    singleLine = true,
                    supportingText = {
                        MaterialText(
                            stringResource(
                                if (isBuiltIn) R.string.theme_store_builtin_token_hint
                                else R.string.theme_store_token_hint,
                            ),
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    MaterialText(
                        text = stringResource(R.string.theme_store_token_hidden),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    if (onShowToken != null) {
                        MaterialTextButton(onClick = onShowToken) {
                            MaterialText(stringResource(R.string.theme_store_change_token))
                        }
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                MaterialText(
                    text = stringResource(R.string.theme_store_source_endpoints),
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                if (endpoints == null) {
                    MaterialText(
                        text = stringResource(R.string.theme_store_source_invalid),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                MaterialTextButton(
                    onClick = { endpointsExpanded = !endpointsExpanded },
                ) {
                    MaterialText(
                        stringResource(
                            if (endpointsExpanded) R.string.theme_store_collapse_endpoints
                            else R.string.theme_store_expand_endpoints,
                        ),
                    )
                }
            }
            if (endpointsExpanded) {
                EndpointRowsMaterial(endpoints = endpoints)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(modifier = Modifier.weight(1f)) {
                    SourceTestTextMaterial(test)
                }
                MaterialTextButton(onClick = onTest) {
                    MaterialText(stringResource(R.string.theme_store_source_test))
                }
            }
        }
    }
}

@Composable
private fun EndpointRowsMaterial(
    endpoints: SourceEndpoints?,
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (endpoints == null) {
                MaterialText(
                    text = stringResource(R.string.theme_store_source_invalid),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            } else {
                EndpointRowMaterial(stringResource(R.string.theme_store_catalog_endpoint), endpoints.catalog)
                EndpointRowMaterial(stringResource(R.string.theme_store_themes_endpoint), endpoints.themes)
                EndpointRowMaterial(stringResource(R.string.theme_store_previews_endpoint), endpoints.previews)
                EndpointRowMaterial(stringResource(R.string.theme_store_avatars_endpoint), endpoints.avatars)
                EndpointRowMaterial(stringResource(R.string.theme_store_health_endpoint), endpoints.health)
                EndpointRowMaterial(stringResource(R.string.theme_store_token_header), endpoints.tokenHeader)
            }
        }
    }
}

@Composable
private fun EndpointRowMaterial(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        MaterialText(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        MaterialText(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun SourceTestTextMaterial(test: SourceTestState?) {
    when (test) {
        SourceTestState.Testing -> MaterialText(
            text = stringResource(R.string.theme_store_source_testing),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
        )
        is SourceTestState.Success -> MaterialText(
            text = stringResource(
                if (test.cached) R.string.theme_store_source_test_cache
                else R.string.theme_store_source_test_ok,
                test.themes,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
        )
        is SourceTestState.Failure -> MaterialText(
            text = stringResource(R.string.theme_store_source_test_failed) + " · " + test.message,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        null -> Unit
    }
}

private fun extraTestKey(source: ThemeStoreSourceConfig): String = "extra:${source.id}"

private fun endpointsFor(baseUrl: String): SourceEndpoints? {
    val base = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return null
    return SourceEndpoints(
        catalog = base + "catalog.json",
        themes = base + "themes/",
        previews = base + "previews/",
        avatars = base + "avatars/",
        health = base + "health",
        tokenHeader = ThemeStoreRepository.TOKEN_HEADER,
    )
}
