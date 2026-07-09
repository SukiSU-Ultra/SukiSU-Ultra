package com.sukisu.ultra.ui.screen.umountmanager

import android.annotation.SuppressLint
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.dialog.ConfirmResult
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@SuppressLint("LocalContextGetResourceValueCall")
@Composable
fun UmountManagerScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val confirmDialog = rememberConfirmDialog()

    var pathList by remember { mutableStateOf<List<UmountPathEntry>>(emptyList()) }
    var exclusionList by remember { mutableStateOf<List<UmountExclusionEntry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var showAddPathDialog by remember { mutableStateOf(false) }
    var showAddExclusionDialog by remember { mutableStateOf(false) }
    var showExclusionList by remember { mutableStateOf(false) }

    val confirmActionText = stringResource(R.string.confirm_action)
    val umountPathRemovedText = stringResource(R.string.umount_path_removed)
    val confirmClearCustomPathsText = stringResource(R.string.confirm_clear_custom_paths)
    val customPathsClearedText = stringResource(R.string.custom_paths_cleared)
    val operationFailedText = stringResource(R.string.operation_failed)
    val configAppliedText = stringResource(R.string.config_applied)
    val umountPathAddedText = stringResource(R.string.umount_path_added)
    val confirmDelete = stringResource(R.string.confirm_delete)
    val umountExclusionAddedText = stringResource(R.string.umount_exclusion_added)
    val umountExclusionRemovedText = stringResource(R.string.umount_exclusion_removed)
    val confirmClearExclusionsText = stringResource(R.string.confirm_clear_exclusions)
    val exclusionsClearedText = stringResource(R.string.umount_exclusion_cleared)

    fun loadPaths() {
        scope.launch(Dispatchers.IO) {
            isLoading = true
            val result = listUmountPaths()
            val entries = parseUmountPaths(result)
            withContext(Dispatchers.Main) {
                pathList = entries
                isLoading = false
            }
        }
    }

    fun loadExclusions() {
        scope.launch(Dispatchers.IO) {
            isLoading = true
            val result = listUmountExclusions()
            val entries = parseUmountExclusions(result)
            withContext(Dispatchers.Main) {
                exclusionList = entries
                isLoading = false
            }
        }
    }

    fun loadData() {
        if (showExclusionList) {
            loadExclusions()
        } else {
            loadPaths()
        }
    }

    LaunchedEffect(Unit) {
        loadData()
    }

    val actions = UmountManagerActions(
        onRefresh = { loadData() },
        onAddPathClick = { showAddPathDialog = true },
        onAddPath = { path, flags ->
            showAddPathDialog = false

            scope.launch(Dispatchers.IO) {
                val success = addUmountPath(path, flags)
                withContext(Dispatchers.Main) {
                    if (success) {
                        saveUmountConfig()
                        Toast.makeText(context, umountPathAddedText, Toast.LENGTH_SHORT).show()
                        loadPaths()
                    } else {
                        Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        },
        onDismissAddPathDialog = { showAddPathDialog = false },
        onDeletePath = { pathEntry ->
            scope.launch {
                if (confirmDialog.awaitConfirm(
                        title = confirmDelete,
                        content = context.getString(R.string.confirm_delete_umount_path, pathEntry.path)
                    ) == ConfirmResult.Confirmed) {
                    scope.launch(Dispatchers.IO) {
                        val success = removeUmountPath(pathEntry.path)
                        withContext(Dispatchers.Main) {
                            if (success) {
                                Toast.makeText(context, umountPathRemovedText, Toast.LENGTH_SHORT).show()
                                loadPaths()
                            } else {
                                Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
        },
        onClearCustomPaths = {
            scope.launch {
                if (confirmDialog.awaitConfirm(
                        title = confirmActionText,
                        content = confirmClearCustomPathsText
                    ) == ConfirmResult.Confirmed) {
                    withContext(Dispatchers.IO) {
                        val success = clearCustomUmountPaths()
                        withContext(Dispatchers.Main) {
                            if (success) {
                                Toast.makeText(context, customPathsClearedText, Toast.LENGTH_SHORT).show()
                                loadPaths()
                            } else {
                                Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
        },
        onApplyConfig = {
            scope.launch(Dispatchers.IO) {
                val success = applyUmountConfigToKernel()
                withContext(Dispatchers.Main) {
                    if (success) {
                        Toast.makeText(context, configAppliedText, Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        },
        onBack = { navigator.pop() },
        // Exclusion actions
        onShowExclusionList = { showExclusionList = true },
        onAddExclusionClick = { showAddExclusionDialog = true },
        onAddExclusion = { pathPrefix ->
            showAddExclusionDialog = false

            scope.launch(Dispatchers.IO) {
                val success = addUmountExclusion(pathPrefix)
                withContext(Dispatchers.Main) {
                    if (success) {
                        Toast.makeText(context, umountExclusionAddedText, Toast.LENGTH_SHORT).show()
                        loadExclusions()
                    } else {
                        Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        },
        onDismissAddExclusionDialog = { showAddExclusionDialog = false },
        onDeleteExclusion = { exclusionEntry ->
            scope.launch {
                if (confirmDialog.awaitConfirm(
                        title = confirmDelete,
                        content = "Delete exclusion: ${exclusionEntry.pathPrefix}?"
                    ) == ConfirmResult.Confirmed) {
                    scope.launch(Dispatchers.IO) {
                        val success = removeUmountExclusion(exclusionEntry.pathPrefix)
                        withContext(Dispatchers.Main) {
                            if (success) {
                                Toast.makeText(context, umountExclusionRemovedText, Toast.LENGTH_SHORT).show()
                                loadExclusions()
                            } else {
                                Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
        },
        onClearAllExclusions = {
            scope.launch {
                if (confirmDialog.awaitConfirm(
                        title = confirmActionText,
                        content = confirmClearExclusionsText
                    ) == ConfirmResult.Confirmed) {
                    withContext(Dispatchers.IO) {
                        val success = clearUmountExclusions()
                        withContext(Dispatchers.Main) {
                            if (success) {
                                Toast.makeText(context, exclusionsClearedText, Toast.LENGTH_SHORT).show()
                                loadExclusions()
                            } else {
                                Toast.makeText(context, operationFailedText, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
        },
        onBackToPathList = { showExclusionList = false },
    )

    val state = UmountManagerUiState(
        pathList = pathList,
        exclusionList = exclusionList,
        isLoading = isLoading,
        showAddPathDialog = showAddPathDialog,
        showAddExclusionDialog = showAddExclusionDialog,
        showExclusionList = showExclusionList,
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> UmountManagerMiuix(
            state = state,
            actions = actions
        )
        UiMode.Material -> UmountManagerMaterial(
            state = state,
            actions = actions
        )
    }
}
