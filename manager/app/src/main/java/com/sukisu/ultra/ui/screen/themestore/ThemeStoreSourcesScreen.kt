package com.sukisu.ultra.ui.screen.themestore

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import androidx.compose.runtime.LaunchedEffect
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
import com.sukisu.ultra.data.repository.ThemeStoreHealthError
import com.sukisu.ultra.data.repository.ThemeStoreHealthException
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
    data class Success(
        val themes: Int,
        val cached: Boolean,
        val notModified: Boolean,
    ) : SourceTestState
    data class Failure(val message: String) : SourceTestState
}

private sealed interface SourceHealthState {
    data object Checking : SourceHealthState
    data class Success(
        val ok: Boolean,
        val status: String,
        val latencyMs: Long,
        val databaseLatencyMs: Long?,
        val themes: Int?,
        val pending: Int?,
        val version: String?,
    ) : SourceHealthState
    data class Failure(val message: String) : SourceHealthState
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
    val builtInBases = remember {
        ThemeStoreDefaults.BASE_URLS
            .mapNotNull { ThemeStoreRepository.normalizeBaseUrl(it) }
            .toSet()
    }

    var defaultBase by rememberSaveable(settings.themeStoreBaseUrl) {
        mutableStateOf(ThemeStoreDefaults.resolveConfiguredBaseUrl(settings.themeStoreBaseUrl))
    }
    var keepAutoDefault by rememberSaveable(settings.themeStoreBaseUrl) {
        mutableStateOf(ThemeStoreDefaults.usesAutoBaseUrl(settings.themeStoreBaseUrl))
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
    var healthChecks by remember { mutableStateOf<Map<String, SourceHealthState>>(emptyMap()) }
    var showSaveError by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        if (keepAutoDefault) {
            defaultBase = ThemeStoreDefaults.resolveBestBaseUrl()
        }
    }

    val normalizedDefault = ThemeStoreRepository.normalizeBaseUrl(
        defaultBase.ifBlank { ThemeStoreDefaults.resolveConfiguredBaseUrl(settings.themeStoreBaseUrl) },
    )
    val isBuiltIn = normalizedDefault != null && normalizedDefault in builtInBases
    val showDefaultToken = showBuiltInToken || !isBuiltIn || defaultToken.isNotBlank()
    val effectiveDefaultBase = defaultBase.ifBlank {
        ThemeStoreDefaults.resolveConfiguredBaseUrl(settings.themeStoreBaseUrl)
    }
    val defaultEndpoints = endpointsFor(effectiveDefaultBase)
    val effectiveDefaultToken = defaultToken.trim().ifBlank {
        ""
    }

    fun updateExtra(index: Int, source: ThemeStoreSourceConfig) {
        extraSources = extraSources.toMutableList().also { it[index] = source }
        tests = tests - extraTestKey(source)
        healthChecks = healthChecks - extraTestKey(source)
        showSaveError = false
    }

    fun removeExtra(index: Int) {
        val source = extraSources.getOrNull(index)
        extraSources = extraSources.toMutableList().also { it.removeAt(index) }
        if (source != null) {
            tests = tests - extraTestKey(source)
            healthChecks = healthChecks - extraTestKey(source)
        }
        showSaveError = false
    }

    @SuppressLint("LocalContextGetResourceValueCall")
    fun testSource(key: String, baseUrl: String, token: String) {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl)
        if (normalized == null) {
            val message = context.getString(R.string.theme_store_source_invalid)
            tests = tests + (key to SourceTestState.Failure(message))
            healthChecks = healthChecks + (key to SourceHealthState.Failure(message))
            return
        }
        tests = tests + (key to SourceTestState.Testing)
        healthChecks = healthChecks + (key to SourceHealthState.Checking)
        // Catalog and health run in parallel so one click checks both.
        scope.launch {
            val result = repository.loadCatalog(normalized, token)
            tests = tests + (
                key to result.fold(
                    onSuccess = {
                        SourceTestState.Success(
                            themes = it.catalog.themes.size,
                            cached = it.fromCache,
                            notModified = it.notModified,
                        )
                    },
                    onFailure = {
                        SourceTestState.Failure(
                            it.message?.takeIf { message -> message.isNotBlank() }
                                ?: context.getString(R.string.theme_store_source_test_failed),
                        )
                    },
                )
            )
        }
        scope.launch {
            val result = repository.checkHealth(normalized, token)
            healthChecks = healthChecks + (
                key to result.fold(
                    onSuccess = { value ->
                        val health = value.health
                        SourceHealthState.Success(
                            ok = health.ok,
                            status = health.status.ifBlank {
                                if (health.ok) "ok" else "down"
                            },
                            latencyMs = value.latencyMs,
                            databaseLatencyMs = health.checks.database.latencyMs,
                            themes = health.checks.catalog.themes,
                            pending = health.checks.pending.count,
                            version = health.version.takeIf { it.isNotBlank() },
                        )
                    },
                    onFailure = { error ->
                        val message = when (error) {
                            is ThemeStoreHealthException -> when (error.error) {
                                ThemeStoreHealthError.INVALID_URL ->
                                    context.getString(R.string.theme_store_source_invalid)
                                ThemeStoreHealthError.NON_JSON ->
                                    context.getString(R.string.theme_store_health_non_json)
                                ThemeStoreHealthError.EMPTY_RESPONSE ->
                                    context.getString(R.string.theme_store_health_empty)
                                ThemeStoreHealthError.INVALID_RESPONSE ->
                                    context.getString(R.string.theme_store_health_invalid_response)
                                ThemeStoreHealthError.HTTP -> context.getString(
                                    R.string.theme_store_health_http_error,
                                    error.httpStatus ?: 0,
                                )
                            }
                            else -> context.getString(
                                R.string.theme_store_health_network_error,
                            )
                        }
                        SourceHealthState.Failure(message)
                    },
                )
            )
        }
    }

    fun save() {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(
            defaultBase.ifBlank { ThemeStoreDefaults.resolveConfiguredBaseUrl(settings.themeStoreBaseUrl) },
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
        settingsViewModel.setThemeStoreBaseUrl(if (keepAutoDefault) "" else normalized)
        settingsViewModel.setThemeStoreToken(defaultToken.trim())
        settingsViewModel.setThemeStoreAdminUrl("")
        settingsViewModel.setThemeStoreExtraSources(cleaned)
        navigator.setResult(THEME_SOURCES_RESULT_KEY, true)
    }

    ThemeStoreSourcesMaterial(
        defaultBase = defaultBase,
        onDefaultBaseChange = {
            defaultBase = it
            keepAutoDefault = false
            tests = tests - "default"
            healthChecks = healthChecks - "default"
            showSaveError = false
        },
        defaultIsAuto = keepAutoDefault,
        onDefaultBaseSelect = { selected ->
            if (selected == null) {
                keepAutoDefault = true
                defaultBase = ThemeStoreDefaults.resolveBestBaseUrl()
            } else {
                keepAutoDefault = false
                defaultBase = selected
            }
            tests = tests - "default"
            healthChecks = healthChecks - "default"
            showSaveError = false
        },
        defaultToken = defaultToken,
        onDefaultTokenChange = {
            defaultToken = it
            tests = tests - "default"
            healthChecks = healthChecks - "default"
            showSaveError = false
        },
        showDefaultToken = showDefaultToken,
        onShowToken = { showBuiltInToken = true },
        isBuiltIn = isBuiltIn,
        defaultEndpoints = defaultEndpoints,
        defaultTest = tests["default"],
        onTestDefault = { testSource("default", effectiveDefaultBase, effectiveDefaultToken) },
        onResetAccess = { base ->
            scope.launch {
                repository.resetAccess(base).onSuccess {
                    if (ThemeStoreRepository.normalizeBaseUrl(base) == normalizedDefault) defaultToken = ""
                    extraSources = extraSources.map { source ->
                        if (ThemeStoreRepository.normalizeBaseUrl(source.baseUrl) == ThemeStoreRepository.normalizeBaseUrl(base)) source.copy(token = "") else source
                    }
                    tests = emptyMap()
                    healthChecks = emptyMap()
                }.onFailure { error ->
                    tests = tests + ("default" to SourceTestState.Failure(error.message.orEmpty()))
                }
            }
        },
        defaultHealth = healthChecks["default"],
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
        healthChecks = healthChecks,
        showSaveError = showSaveError,
        onSave = ::save,
        onBack = { navigator.pop() },
    )
}

@Composable
private fun ThemeStoreSourcesMaterial(
    defaultBase: String,
    onDefaultBaseChange: (String) -> Unit,
    defaultIsAuto: Boolean,
    onDefaultBaseSelect: (String?) -> Unit,
    defaultToken: String,
    onDefaultTokenChange: (String) -> Unit,
    showDefaultToken: Boolean,
    onShowToken: () -> Unit,
    isBuiltIn: Boolean,
    defaultEndpoints: SourceEndpoints?,
    defaultTest: SourceTestState?,
    onTestDefault: () -> Unit,
    onResetAccess: (String) -> Unit,
    defaultHealth: SourceHealthState?,
    extraSources: List<ThemeStoreSourceConfig>,
    onUpdateExtra: (Int, ThemeStoreSourceConfig) -> Unit,
    onRemoveExtra: (Int) -> Unit,
    onAddExtra: () -> Unit,
    tests: Map<String, SourceTestState>,
    onTestExtra: (ThemeStoreSourceConfig) -> Unit,
    healthChecks: Map<String, SourceHealthState>,
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
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    ThemeStoreDefaultMirrorPicker(
                        selected = if (defaultIsAuto) null else defaultBase,
                        onSelect = onDefaultBaseSelect,
                    )
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
                        onResetAccess = { onResetAccess(defaultBase) },
                        health = defaultHealth,
                    )
                }
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
                    onResetAccess = { onResetAccess(source.baseUrl) },
                    health = healthChecks[extraTestKey(source)],
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

/**
 * Manual mirror choice. "Automatic" follows the region/VPN rule; picking a
 * built-in mirror stores it forever, so later region changes cannot override
 * the user's choice.
 */
@Composable
private fun ThemeStoreDefaultMirrorPicker(
    selected: String?,
    onSelect: (String?) -> Unit,
) {
    val normalizedSelected = selected?.let { ThemeStoreRepository.normalizeBaseUrl(it) }
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        FilterChip(
            selected = normalizedSelected == null,
            onClick = { onSelect(null) },
            label = { MaterialText(stringResource(R.string.theme_store_default_auto)) },
            shapes = FilterChipDefaults.shapes(),
        )
        ThemeStoreDefaults.BASE_URLS.forEach { base ->
            val normalized = ThemeStoreRepository.normalizeBaseUrl(base) ?: return@forEach
            FilterChip(
                selected = normalizedSelected == normalized,
                onClick = { onSelect(normalized) },
                label = {
                    MaterialText(
                        base.removePrefix("https://")
                            .removePrefix("http://")
                            .trimEnd('/'),
                    )
                },
                shapes = FilterChipDefaults.shapes(),
            )
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
    onResetAccess: () -> Unit,
    health: SourceHealthState?,
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
            MaterialTextButton(onClick = onResetAccess) {
                MaterialText(stringResource(R.string.theme_store_device_reauthorize))
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
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    SourceTestTextMaterial(test)
                    SourceHealthTextMaterial(health)
                }
                MaterialTextButton(
                    onClick = onTest,
                    enabled = test != SourceTestState.Testing &&
                        health != SourceHealthState.Checking,
                ) {
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
            text = when {
                test.cached -> stringResource(
                    R.string.theme_store_source_test_cache,
                    test.themes,
                )
                test.notModified -> stringResource(
                    R.string.theme_store_source_test_unchanged,
                    test.themes,
                )
                else -> stringResource(
                    R.string.theme_store_source_test_ok,
                    test.themes,
                )
            },
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

@Composable
private fun SourceHealthTextMaterial(health: SourceHealthState?) {
    when (health) {
        SourceHealthState.Checking -> MaterialText(
            text = stringResource(R.string.theme_store_health_checking),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
        )
        is SourceHealthState.Success -> {
            val statusLabel = when {
                health.status.equals("ok", ignoreCase = true) ->
                    stringResource(R.string.theme_store_health_ok)
                health.status.equals("degraded", ignoreCase = true) ->
                    stringResource(R.string.theme_store_health_degraded)
                health.status.equals("down", ignoreCase = true) ->
                    stringResource(R.string.theme_store_health_down)
                else -> health.status.ifBlank {
                    stringResource(R.string.theme_store_health_unknown)
                }
            }
            val color = when {
                !health.ok -> MaterialTheme.colorScheme.error
                health.status.equals("degraded", ignoreCase = true) ->
                    MaterialTheme.colorScheme.tertiary
                else -> MaterialTheme.colorScheme.primary
            }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                MaterialText(
                    text = "$statusLabel · ${health.latencyMs} ms",
                    style = MaterialTheme.typography.bodySmall,
                    color = color,
                )
                val details = mutableListOf<String>()
                if (health.themes != null) {
                    details += stringResource(
                        R.string.theme_store_health_details,
                        health.themes,
                        health.pending ?: 0,
                    )
                }
                if (health.databaseLatencyMs != null) {
                    details += stringResource(
                        R.string.theme_store_health_database,
                        health.databaseLatencyMs,
                    )
                }
                if (health.version != null) {
                    details += stringResource(
                        R.string.theme_store_health_version,
                        health.version,
                    )
                }
                if (details.isNotEmpty()) {
                    MaterialText(
                        text = details.joinToString(" · "),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
        is SourceHealthState.Failure -> MaterialText(
            text = stringResource(R.string.theme_store_health_failed) + " · " + health.message,
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
