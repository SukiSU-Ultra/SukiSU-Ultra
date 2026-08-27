package com.sukisu.ultra.ui.screen.settings.tools

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
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.util.spoofCpu
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@SuppressLint("LocalContextGetResourceValueCall", "StringFormatInvalid")
@Composable
fun ToolsScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var selinuxEnforcing by remember { mutableStateOf(true) }
    var selinuxLoading by remember { mutableStateOf(true) }
    var spoofCpuDialogVisible by remember { mutableStateOf(false) }
    var currentCpuInfo by remember { mutableStateOf<CpuInfo?>(null) }
    var spoofCpuLoading by remember { mutableStateOf(false) }

    val backupLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val success = backupAllowlistToUri(context, uri)
            Toast.makeText(
                context,
                context.getString(
                    if (success) R.string.allowlist_backup_success else R.string.allowlist_backup_failed
                ),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    val restoreLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val success = restoreAllowlistFromUri(context, uri)
            Toast.makeText(
                context,
                context.getString(
                    if (success) R.string.allowlist_restore_success else R.string.allowlist_restore_failed
                ),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    LaunchedEffect(Unit) {
        val current = withContext(Dispatchers.IO) { !isSelinuxPermissive() }
        selinuxEnforcing = current
        selinuxLoading = false
        
        currentCpuInfo = withContext(Dispatchers.IO) { readCurrentCpuIdentity() }
    }

    val actions = ToolsActions(
        onBack = { navigator.pop() },
        onSelinuxToggle = { target ->
            selinuxLoading = true
            scope.launch(Dispatchers.IO) {
                val success = if (target) setSelinuxPermissive(false) else setSelinuxPermissive(true)
                val actual = !isSelinuxPermissive()
                withContext(Dispatchers.Main) {
                    selinuxEnforcing = actual
                    selinuxLoading = false
                    Toast.makeText(
                        context,
                        if (success && actual == target) {
                            context.getString(
                                R.string.tools_selinux_apply_success,
                                context.getString(if (actual) R.string.selinux_status_enforcing else R.string.selinux_status_permissive)
                            )
                        } else {
                            context.getString(R.string.tools_selinux_apply_failed)
                        },
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        },
        onBackupAllowlist = {
            backupLauncher.launch("ksu_allowlist_backup.bin")
        },
        onRestoreAllowlist = {
            restoreLauncher.launch(arrayOf("*/*"))
        },
        onNavigateToUmountManager = {
            navigator.push(Route.UmountManager)
        },
        onOpenSpoofCpuDialog = {
            spoofCpuDialogVisible = true
        },
        onDismissSpoofCpuDialog = {
            spoofCpuDialogVisible = false
        },
        onApplySpoofCpu = { params ->
            spoofCpuLoading = true
            scope.launch(Dispatchers.IO) {
                var successCount = 0
                var failCount = 0
                
                for (cpuIndex in params.cpuIndices) {
                    val success = spoofCpu(
                        cpu = cpuIndex,
                        midr = params.midrHex,
                        bogomips = params.bogomips,
                        hwcap = params.hwcapHex,
                        hwcap2 = params.hwcap2Hex
                    )
                    if (success) successCount++ else failCount++
                }
                
                withContext(Dispatchers.Main) {
                    spoofCpuLoading = false
                    spoofCpuDialogVisible = false
                    
                    val message = when {
                        failCount == 0 -> context.getString(R.string.spoof_cpu_apply_success)
                        successCount == 0 -> context.getString(R.string.spoof_cpu_apply_failed)
                        else -> context.getString(R.string.spoof_cpu_apply_partial_failure, successCount, failCount)
                    }
                    
                    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                }
            }
        }
    )

    val state = ToolsUiState(
        selinuxEnforcing = selinuxEnforcing,
        selinuxLoading = selinuxLoading,
        spoofCpuDialogVisible = spoofCpuDialogVisible,
        currentCpuInfo = currentCpuInfo,
        spoofCpuLoading = spoofCpuLoading
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> ToolsMiuix(
            state = state,
            actions = actions
        )
        UiMode.Material -> ToolsMaterial(
            state = state,
            actions = actions
        )
    }

    if (spoofCpuDialogVisible) {
        when (LocalUiMode.current) {
            UiMode.Miuix -> SpoofCpuDialogMiuix(
                currentCpuInfo = currentCpuInfo,
                onDismiss = actions.onDismissSpoofCpuDialog,
                onApply = actions.onApplySpoofCpu
            )
            UiMode.Material -> SpoofCpuDialogMaterial(
                currentCpuInfo = currentCpuInfo,
                onDismiss = actions.onDismissSpoofCpuDialog,
                onApply = actions.onApplySpoofCpu
            )
        }
    }
}
