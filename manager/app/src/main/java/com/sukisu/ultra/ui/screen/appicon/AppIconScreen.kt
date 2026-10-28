package com.sukisu.ultra.ui.screen.appicon

import android.annotation.SuppressLint
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.AppIconPack
import com.sukisu.ultra.ui.util.AppIconPackStorage
import com.sukisu.ultra.ui.util.module.Shortcut
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch

@SuppressLint("LocalContextGetResourceValueCall")
@Composable
fun AppIconScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val viewModel = viewModel<SettingsViewModel>()
    val settings by viewModel.uiState.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    var packs by remember { mutableStateOf<List<AppIconPack>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var importing by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<AppIconPack?>(null) }

    suspend fun reloadPacks() {
        packs = AppIconPackStorage.load(context)
        loading = false
    }

    LaunchedEffect(Unit) {
        reloadPacks()
    }

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            importing = true
            scope.launch {
                try {
                    AppIconPackStorage.import(context, uri)
                        .onSuccess { count ->
                            Toast.makeText(
                                context,
                                context.getString(R.string.app_icon_import_success, count),
                                Toast.LENGTH_SHORT,
                            ).show()
                            reloadPacks()
                        }
                        .onFailure {
                            Toast.makeText(
                                context,
                                R.string.app_icon_import_failed,
                                Toast.LENGTH_LONG,
                            ).show()
                        }
                } finally {
                    importing = false
                }
            }
        }
    }

    val state = AppIconUiState(
        selectedBuiltinId = settings.appIconId,
        packs = packs,
        loading = loading,
        importing = importing,
        pendingDelete = pendingDelete,
    )
    val actions = AppIconActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onSelectBuiltin = { icon ->
            // Re-applying an unchanged component can restart the process on some ROMs.
            if (icon.id != settings.appIconId) {
                viewModel.setAppIcon(context, icon.id)
                Toast.makeText(context, R.string.app_icon_switch_hint, Toast.LENGTH_SHORT).show()
            }
        },
        onImportPack = {
            if (!importing) {
                importLauncher.launch(
                    arrayOf(
                        "application/zip",
                        "application/x-zip",
                        "application/x-zip-compressed",
                        "application/octet-stream",
                    )
                )
            }
        },
        onPinCustomIcon = { pack, entry ->
            scope.launch {
                val bitmap = AppIconPackStorage.loadBitmap(context, pack, entry)
                if (bitmap == null) {
                    Toast.makeText(context, R.string.app_icon_pin_failed, Toast.LENGTH_SHORT).show()
                } else {
                    Shortcut.createAppIconShortcut(
                        context = context,
                        key = "${pack.id}_${entry.id}",
                        label = context.getString(R.string.app_name),
                        bitmap = bitmap,
                    )
                }
            }
        },
        onRequestDeletePack = { pendingDelete = it },
        onDismissDeletePack = { pendingDelete = null },
        onConfirmDeletePack = { pack ->
            pendingDelete = null
            scope.launch {
                AppIconPackStorage.delete(context, pack.id)
                    .onSuccess { reloadPacks() }
                    .onFailure {
                        Toast.makeText(
                            context,
                            R.string.app_icon_delete_pack_failed,
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
            }
        },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> AppIconScreenMiuix(state, actions)
        UiMode.Material -> AppIconScreenMaterial(state, actions)
    }
}
