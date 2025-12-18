package com.sukisu.ultra.ui.screen.settings

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.Scanner
import androidx.compose.material.icons.rounded.Backup
import androidx.compose.material.icons.rounded.FolderDelete
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Security
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.generated.destinations.UmountManagerDestination
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.component.DynamicManagerCard
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.util.cleanRuntimeEnvironment
import com.sukisu.ultra.ui.util.getUidMultiUserScan
import com.sukisu.ultra.ui.util.readUidScannerFile
import com.sukisu.ultra.ui.util.setUidAutoScan
import com.sukisu.ultra.ui.util.setUidMultiUserScan
import com.sukisu.ultra.ui.util.getSELinuxStatus
import com.topjohnwu.superuser.Shell
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.extra.SuperArrow
import top.yukonga.miuix.kmp.extra.SuperSwitch
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.icons.useful.Back
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
@Destination<RootGraph>
fun Tools(
    navigator: DestinationsNavigator
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }
    val hazeStyle = HazeStyle(
        backgroundColor = colorScheme.surface,
        tint = HazeTint(colorScheme.surface.copy(0.8f))
    )
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("settings", Context.MODE_PRIVATE) }

    Scaffold(
        topBar = {
            TopAppBar(
                modifier = Modifier.hazeEffect(hazeState) {
                    style = hazeStyle
                    blurRadius = 30.dp
                    noiseFactor = 0f
                },
                color = Color.Transparent,
                title = stringResource(R.string.tools),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        Icon(
                            imageVector = MiuixIcons.Useful.Back,
                            contentDescription = "Back"
                        )
                    }
                }
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .hazeSource(state = hazeState)
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                KsuIsValid {
                    SelinuxToggleSection(scope = scope, context = context)

                    DynamicManagerCard()

                    Card(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        val umontManager = stringResource(id = R.string.umount_path_manager)
                        SuperArrow(
                            title = umontManager,
                            leftAction = {
                                Icon(
                                    Icons.Rounded.FolderDelete,
                                    modifier = Modifier.padding(end = 16.dp),
                                    contentDescription = umontManager,
                                    tint = colorScheme.onBackground
                                )
                            },
                            onClick = {
                                navigator.navigate(UmountManagerDestination)
                            }
                        )
                    }
                    
                    AllowlistBackupSection(scope = scope, context = context)
                }
            }
        }
    }
}

@Composable
fun SelinuxToggleSection(
    scope: CoroutineScope,
    context: Context
) {
    var selinuxEnforcing by remember { mutableStateOf(true) }
    var selinuxLoading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        val current = withContext(Dispatchers.IO) { !isSelinuxPermissive() }
        selinuxEnforcing = current
        selinuxLoading = false
    }

    Card(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        val statusLabel = getSELinuxStatus()
        SuperSwitch(
            title = stringResource(R.string.tools_selinux_toggle),
            summary = stringResource(
                R.string.tools_selinux_summary,
                statusLabel
            ),
            leftAction = {
                Icon(
                    imageVector = Icons.Rounded.Security,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(id = R.string.tools_selinux_toggle),
                    tint = colorScheme.onBackground
                )
            },
            checked = selinuxEnforcing,
            enabled = !selinuxLoading,
            onCheckedChange = { target ->
                selinuxLoading = true
                scope.launch(Dispatchers.IO) {
                    val success = if (target) {
                        setSelinuxPermissive(false)
                    } else {
                        setSelinuxPermissive(true)
                    }
                    val actual = !isSelinuxPermissive()
                    withContext(Dispatchers.Main) {
                        selinuxEnforcing = actual
                        selinuxLoading = false
                        Toast.makeText(
                            context,
                            if (success && actual == target) {
                                context.getString(
                                    R.string.tools_selinux_apply_success,
                                    context.getString(
                                        if (actual) {
                                            R.string.selinux_status_enforcing
                                        } else {
                                            R.string.selinux_status_permissive
                                        }
                                    )
                                )
                            } else {
                                context.getString(R.string.tools_selinux_apply_failed)
                            },
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        )
    }
}

@Composable
private fun AllowlistBackupSection(
    scope: CoroutineScope,
    context: Context
) {
    val contextRef = remember { context }

    val backupLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri == null) {
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            val success = backupAllowlistToUri(contextRef, uri)
            Toast.makeText(
                contextRef,
                contextRef.getString(
                    if (success) {
                        R.string.allowlist_backup_success
                    } else {
                        R.string.allowlist_backup_failed
                    }
                ),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    val restoreLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) {
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            val success = restoreAllowlistFromUri(contextRef, uri)
            Toast.makeText(
                contextRef,
                contextRef.getString(
                    if (success) {
                        R.string.allowlist_restore_success
                    } else {
                        R.string.allowlist_restore_failed
                    }
                ),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    Card(
        modifier = Modifier
            .padding(vertical = 12.dp)
            .fillMaxWidth(),
    ) {
        SuperArrow(
            title = stringResource(R.string.allowlist_backup_title),
            summary = stringResource(R.string.allowlist_backup_summary_picker),
            leftAction = {
                Icon(
                    imageVector = Icons.Rounded.Backup,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.allowlist_backup_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = {
                backupLauncher.launch("ksu_allowlist_backup.bin")
            }
        )

        SuperArrow(
            title = stringResource(R.string.allowlist_restore_title),
            summary = stringResource(R.string.allowlist_restore_summary_picker),
            leftAction = {
                Icon(
                    imageVector = Icons.Rounded.Restore,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.allowlist_restore_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = {
                restoreLauncher.launch(arrayOf("*/*"))
            }
        )
    }
}

private fun isSelinuxPermissive(): Boolean {
    val result = Shell.cmd("getenforce").exec()
    val output = result.out.joinToString("\n").trim().lowercase()
    return output == "permissive"
}

private fun setSelinuxPermissive(permissive: Boolean): Boolean {
    val target = if (permissive) "0" else "1"
    val result = Shell.cmd("setenforce $target").exec()
    return result.isSuccess
}

private suspend fun backupAllowlistToUri(context: Context, targetUri: Uri): Boolean = withContext(Dispatchers.IO) {
    val tempFile = File(context.cacheDir, "allowlist_backup_tmp.bin")
    try {
        if (!copyAllowlistToFile(tempFile)) return@withContext false
        return@withContext runCatching {
            context.contentResolver.openOutputStream(targetUri, "w")?.use { output ->
                tempFile.inputStream().use { input ->
                    input.copyTo(output)
                }
                true
            } ?: false
        }.getOrElse { false }
    } finally {
        tempFile.delete()
    }
}

private suspend fun restoreAllowlistFromUri(context: Context, sourceUri: Uri): Boolean = withContext(Dispatchers.IO) {
    val tempFile = File(context.cacheDir, "allowlist_restore_tmp.bin")
    try {
        val downloaded = runCatching {
            context.contentResolver.openInputStream(sourceUri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
                true
            } ?: false
        }.getOrElse { false }
        if (!downloaded) return@withContext false
        return@withContext copyFileToAllowlist(tempFile)
    } finally {
        tempFile.delete()
    }
}

private suspend fun copyAllowlistToFile(targetFile: File): Boolean = withContext(Dispatchers.IO) {
    runCatching {
        targetFile.parentFile?.mkdirs()
        val result = Shell.cmd(
            "cp /data/adb/ksu/.allowlist \"${targetFile.absolutePath}\"",
            "chmod 0644 \"${targetFile.absolutePath}\""
        ).exec()
        result.isSuccess
    }.getOrDefault(false)
}

private suspend fun copyFileToAllowlist(sourceFile: File): Boolean = withContext(Dispatchers.IO) {
    if (!sourceFile.exists()) return@withContext false
    runCatching {
        val result = Shell.cmd(
            "cp \"${sourceFile.absolutePath}\" /data/adb/ksu/.allowlist",
            "chmod 0644 /data/adb/ksu/.allowlist"
        ).exec()
        result.isSuccess
    }.getOrDefault(false)
}
