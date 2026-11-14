package com.sukisu.ultra.ui.screen.module

import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.Module
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Shared banner editing state for the module information dialogs. Writes happen on IO; the
 * dialog stays open and [onChanged] asks the pager to re-read the module list.
 */
@Stable
class ModuleInfoBannerState internal constructor(
    private val context: Context,
    private val module: Module,
    private val scope: CoroutineScope,
    private val onChanged: () -> Unit,
) {
    var busy by mutableStateOf(false)
        private set

    fun import(uri: Uri) {
        if (busy) return
        busy = true
        scope.launch {
            val result = withContext(Dispatchers.IO) { ModuleBannerEditor.import(context, module, uri) }
            busy = false
            if (result.isSuccess) invalidateModuleBanner(module.id)
            val message = if (result.isSuccess) {
                R.string.module_info_banner_saved
            } else {
                R.string.module_info_banner_failed
            }
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            if (result.isSuccess) onChanged()
        }
    }

    fun remove() {
        if (busy) return
        busy = true
        scope.launch {
            val result = withContext(Dispatchers.IO) { ModuleBannerEditor.remove(module) }
            busy = false
            if (result.isSuccess) invalidateModuleBanner(module.id)
            val message = if (result.isSuccess) {
                R.string.module_info_banner_removed
            } else {
                R.string.module_info_banner_failed
            }
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            if (result.isSuccess) onChanged()
        }
    }
}

@Composable
fun rememberModuleInfoBannerState(
    module: Module,
    onChanged: () -> Unit,
): ModuleInfoBannerState {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val latestOnChanged by rememberUpdatedState(onChanged)
    return remember(module.id, context, scope) {
        ModuleInfoBannerState(context, module, scope) { latestOnChanged() }
    }
}

/** Launcher for picking a banner image; copies the result immediately, so no URI grant is kept. */
@Composable
fun rememberModuleBannerPicker(state: ModuleInfoBannerState): () -> Unit {
    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let(state::import)
    }
    return remember(launcher) { { launcher.launch(arrayOf("image/*")) } }
}
