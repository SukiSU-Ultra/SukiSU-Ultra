package zako.zako.zako.zakoui.screen.moreSettings.component

import android.content.Context
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.maxkeppeker.sheets.core.models.base.Header
import com.maxkeppeker.sheets.core.models.base.rememberUseCaseState
import com.maxkeppeler.sheets.list.ListDialog
import com.maxkeppeler.sheets.list.models.ListOption
import com.maxkeppeler.sheets.list.models.ListSelection
import zako.zako.zako.zakoui.screen.moreSettings.util.LocaleHelper
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.*
import zako.zako.zako.zakoui.screen.moreSettings.MoreSettingsHandlers
import zako.zako.zako.zakoui.screen.moreSettings.state.MoreSettingsState

@Composable
fun MoreSettingsDialogs(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    // 主题模式选择对话框
    if (state.showThemeModeDialog) {
        SingleChoiceDialog(
            title = stringResource(R.string.theme_mode),
            options = state.themeOptions,
            selectedIndex = state.themeMode,
            onOptionSelected = { index ->
                handlers.handleThemeModeChange(index)
            },
            onDismiss = { state.showThemeModeDialog = false }
        )
    }

    // DPI 设置确认对话框
    if (state.showDpiConfirmDialog) {
        ConfirmDialog(
            title = stringResource(R.string.dpi_confirm_title),
            message = stringResource(R.string.dpi_confirm_message, state.currentDpi, state.tempDpi),
            summaryText = stringResource(R.string.dpi_confirm_summary),
            confirmText = stringResource(R.string.confirm),
            dismissText = stringResource(R.string.cancel),
            onConfirm = { handlers.handleDpiApply() },
            onDismiss = {
                state.showDpiConfirmDialog = false
                state.tempDpi = state.currentDpi
            }
        )
    }

    // 主题色选择对话框
    if (state.showThemeColorDialog) {
        ThemeColorDialog(
            onColorSelected = { theme ->
                handlers.handleThemeColorChange(theme)
                state.showThemeColorDialog = false
            },
            onDismiss = { state.showThemeColorDialog = false }
        )
    }

    // 动态管理器配置对话框
    if (state.showDynamicSignDialog) {
        DynamicManagerDialog(
            state = state,
            onConfirm = { enabled, size, hash ->
                handlers.handleDynamicManagerConfig(enabled, size, hash)
                state.showDynamicSignDialog = false
            },
            onDismiss = { state.showDynamicSignDialog = false }
        )
    }
}

@Composable
fun SingleChoiceDialog(
    title: String,
    options: List<String>,
    selectedIndex: Int,
    onOptionSelected: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                options.forEachIndexed { index, option ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onOptionSelected(index)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedIndex == index,
                            onClick = null
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(option)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
fun ConfirmDialog(
    title: String,
    message: String,
    summaryText: String? = null,
    confirmText: String = stringResource(R.string.confirm),
    dismissText: String = stringResource(R.string.cancel),
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(message)
                if (summaryText != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        summaryText,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(confirmText)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(dismissText)
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LanguageSelectionDialog(
    onLanguageSelected: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    // Check if should use system language settings
    if (LocaleHelper.useSystemLanguageSettings) {
        // Android 13+ - Jump to system settings
        LocaleHelper.launchSystemLanguageSettings(context)
        onDismiss()
    } else {
        // Android < 13 - Show app language selector
        // Dynamically detect supported locales from resources
        val supportedLocales = remember {
            val locales = mutableListOf<java.util.Locale>()

            // Add system default first
            locales.add(java.util.Locale.ROOT) // This will represent "System Default"

            // Dynamically detect available locales by checking resource directories
            val resourceDirs = listOf(
                "ar", "bg", "de", "fa", "fr", "hu", "in", "it",
                "ja", "ko", "pl", "pt-rBR", "ru", "th", "tr",
                "uk", "vi", "zh-rCN", "zh-rTW"
            )

            resourceDirs.forEach { dir ->
                try {
                    val locale = when {
                        dir.contains("-r") -> {
                            val parts = dir.split("-r")
                            java.util.Locale.Builder()
                                .setLanguage(parts[0])
                                .setRegion(parts[1])
                                .build()
                        }
                        else -> java.util.Locale.Builder()
                            .setLanguage(dir)
                            .build()
                    }

                    // Test if this locale has translated resources
                    val config = android.content.res.Configuration()
                    config.setLocale(locale)
                    val localizedContext = context.createConfigurationContext(config)

                    // Try to get a translated string to verify the locale is supported
                    val testString = localizedContext.getString(R.string.settings_language)
                    val defaultString = context.getString(R.string.settings_language)

                    // If the string is different or it's English, it's supported
                    if (testString != defaultString || locale.language == "en") {
                        locales.add(locale)
                    }
                } catch (_: Exception) {
                    // Skip unsupported locales
                }
            }

            // Sort by display name
            val sortedLocales = locales.drop(1).sortedBy { it.getDisplayName(it) }
            mutableListOf<java.util.Locale>().apply {
                add(locales.first()) // System default first
                addAll(sortedLocales)
            }
        }

        val allOptions = supportedLocales.map { locale ->
            val tag = if (locale == java.util.Locale.ROOT) {
                "system"
            } else if (locale.country.isEmpty()) {
                locale.language
            } else {
                "${locale.language}_${locale.country}"
            }

            val displayName = if (locale == java.util.Locale.ROOT) {
                context.getString(R.string.language_system_default)
            } else {
                locale.getDisplayName(locale)
            }

            tag to displayName
        }

        val currentLocale = prefs.getString("app_locale", "system") ?: "system"
        val options = allOptions.map { (tag, displayName) ->
            ListOption(
                titleText = displayName,
                selected = currentLocale == tag
            )
        }

        var selectedIndex by remember {
            mutableIntStateOf(allOptions.indexOfFirst { (tag, _) -> currentLocale == tag })
        }

        ListDialog(
            state = rememberUseCaseState(
                visible = true,
                onFinishedRequest = {
                    if (selectedIndex >= 0 && selectedIndex < allOptions.size) {
                        val newLocale = allOptions[selectedIndex].first
                        prefs.edit { putString("app_locale", newLocale) }
                        onLanguageSelected(newLocale)
                    }
                    onDismiss()
                },
                onCloseRequest = {
                    onDismiss()
                }
            ),
            header = Header.Default(
                title = stringResource(R.string.settings_language),
            ),
            selection = ListSelection.Single(
                showRadioButtons = true,
                options = options
            ) { index, _ ->
                selectedIndex = index
            }
        )
    }
}
@Composable
fun ThemeColorDialog(
    onColorSelected: (ThemeColors) -> Unit,
    onDismiss: () -> Unit
) {
    val themeColorOptions = listOf(
        stringResource(R.string.color_default) to ThemeColors.Default,
        stringResource(R.string.color_green) to ThemeColors.Green,
        stringResource(R.string.color_purple) to ThemeColors.Purple,
        stringResource(R.string.color_orange) to ThemeColors.Orange,
        stringResource(R.string.color_pink) to ThemeColors.Pink,
        stringResource(R.string.color_gray) to ThemeColors.Gray,
        stringResource(R.string.color_yellow) to ThemeColors.Yellow
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.choose_theme_color)) },
        text = {
            Column {
                themeColorOptions.forEach { (name, theme) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onColorSelected(theme) }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val isDark = isSystemInDarkTheme()
                        Box(
                            modifier = Modifier.padding(end = 12.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                ColorCircle(
                                    color = if (isDark) theme.primaryDark else theme.primaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                                ColorCircle(
                                    color = if (isDark) theme.secondaryDark else theme.secondaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                                ColorCircle(
                                    color = if (isDark) theme.tertiaryDark else theme.tertiaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                            }
                        }
                        Text(name)
                        Spacer(modifier = Modifier.weight(1f))
                        // 当前选中的主题显示选中标记
                        if (ThemeConfig.currentTheme::class == theme::class) {
                            Icon(
                                Icons.Default.Check,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss
            ) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
fun DynamicManagerDialog(
    state: MoreSettingsState,
    onConfirm: (Boolean, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var localEnabled by remember { mutableStateOf(state.isDynamicSignEnabled) }
    var localSize by remember { mutableStateOf(state.dynamicSignSize) }
    var localHash by remember { mutableStateOf(state.dynamicSignHash) }

    fun parseDynamicSignSize(input: String): Int? {
        return try {
            when {
                input.startsWith("0x", true) -> input.substring(2).toInt(16)
                else -> input.toInt()
            }
        } catch (_: NumberFormatException) {
            null
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.dynamic_manager_title)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState())
            ) {
                // 启用开关
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { localEnabled = !localEnabled }
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Switch(
                        checked = localEnabled,
                        onCheckedChange = { localEnabled = it }
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(stringResource(R.string.enable_dynamic_manager))
                }

                Spacer(modifier = Modifier.height(16.dp))

                // 签名大小输入
                OutlinedTextField(
                    value = localSize,
                    onValueChange = { input ->
                        val isValid = when {
                            input.isEmpty() -> true
                            input.matches(Regex("^\\d+$")) -> true
                            input.matches(Regex("^0[xX][0-9a-fA-F]*$")) -> true
                            else -> false
                        }
                        if (isValid) {
                            localSize = input
                        }
                    },
                    label = { Text(stringResource(R.string.signature_size)) },
                    enabled = localEnabled,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Text
                    )
                )

                Spacer(modifier = Modifier.height(12.dp))

                // 签名哈希输入
                OutlinedTextField(
                    value = localHash,
                    onValueChange = { hash ->
                        if (hash.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                            localHash = hash
                        }
                    },
                    label = { Text(stringResource(R.string.signature_hash)) },
                    enabled = localEnabled,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    supportingText = {
                        Text(stringResource(R.string.hash_must_be_64_chars))
                    },
                    isError = localEnabled && localHash.isNotEmpty() && localHash.length != 64
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(localEnabled, localSize, localHash) },
                enabled = if (localEnabled) {
                    parseDynamicSignSize(localSize)?.let { it > 0 } == true &&
                            localHash.length == 64
                } else true
            ) {
                Text(stringResource(R.string.confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}