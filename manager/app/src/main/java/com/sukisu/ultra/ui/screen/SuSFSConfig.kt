package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.AddAppPathDialog
import com.sukisu.ultra.ui.component.AddKstatStaticallyDialog
import com.sukisu.ultra.ui.component.AddPathDialog
import com.sukisu.ultra.ui.component.AddTryUmountDialog
import com.sukisu.ultra.ui.component.ConfirmDialog
import com.sukisu.ultra.ui.component.EnabledFeaturesContent
import com.sukisu.ultra.ui.component.KstatConfigContent
import com.sukisu.ultra.ui.component.PathSettingsContent
import com.sukisu.ultra.ui.component.SusMountsContent
import com.sukisu.ultra.ui.component.SusPathsContent
import com.sukisu.ultra.ui.component.SusLoopPathsContent
import com.sukisu.ultra.ui.component.TryUmountContent
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.util.SuSFSManager
import com.sukisu.ultra.ui.util.SuSFSManager.isSusVersion158
import com.sukisu.ultra.ui.util.SuSFSManager.isSusVersion159
import com.sukisu.ultra.ui.util.isAbDevice
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * 标签页枚举类
 */
enum class SuSFSTab(val displayNameRes: Int) {
    BASIC_SETTINGS(R.string.susfs_tab_basic_settings),
    SUS_PATHS(R.string.susfs_tab_sus_paths),
    SUS_LOOP_PATHS(R.string.susfs_tab_sus_loop_paths),
    SUS_MOUNTS(R.string.susfs_tab_sus_mounts),
    TRY_UMOUNT(R.string.susfs_tab_try_umount),
    KSTAT_CONFIG(R.string.susfs_tab_kstat_config),
    PATH_SETTINGS(R.string.susfs_tab_path_settings),
    ENABLED_FEATURES(R.string.susfs_tab_enabled_features);

    companion object {
        fun getAllTabs(isSusVersion158: Boolean, isSusVersion159: Boolean): List<SuSFSTab> {
            return when {
                isSusVersion159 -> entries.toList()
                isSusVersion158 -> entries.filter { it != SUS_LOOP_PATHS }
                else -> entries.filter { it != PATH_SETTINGS && it != SUS_LOOP_PATHS }
            }
        }
    }
}

/**
 * SuSFS配置界面
 */
@SuppressLint("SdCardPath", "AutoboxingStateCreation")
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun SuSFSConfigScreen(
    navigator: DestinationsNavigator
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var selectedTab by remember { mutableStateOf(SuSFSTab.BASIC_SETTINGS) }
    var unameValue by remember { mutableStateOf("") }
    var buildTimeValue by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var showConfirmReset by remember { mutableStateOf(false) }
    var autoStartEnabled by remember { mutableStateOf(false) }
    var executeInPostFsData by remember { mutableStateOf(false) }
    var enableHideBl by remember { mutableStateOf(true) }
    var enableCleanupResidue by remember { mutableStateOf(false) }

    // 槽位信息相关状态
    var slotInfoList by remember { mutableStateOf(emptyList<SuSFSManager.SlotInfo>()) }
    var currentActiveSlot by remember { mutableStateOf("") }
    var isLoadingSlotInfo by remember { mutableStateOf(false) }
    var showSlotInfoDialog by remember { mutableStateOf(false) }

    // 路径管理相关状态
    var susPaths by remember { mutableStateOf(emptySet<String>()) }
    var susLoopPaths by remember { mutableStateOf(emptySet<String>()) }
    var susMounts by remember { mutableStateOf(emptySet<String>()) }
    var tryUmounts by remember { mutableStateOf(emptySet<String>()) }
    var androidDataPath by remember { mutableStateOf("") }
    var sdcardPath by remember { mutableStateOf("") }

    // SUS挂载隐藏控制状态
    var hideSusMountsForAllProcs by remember { mutableStateOf(true) }

    var umountForZygoteIsoService by remember { mutableStateOf(false) }

    // Kstat配置相关状态
    var kstatConfigs by remember { mutableStateOf(emptySet<String>()) }
    var addKstatPaths by remember { mutableStateOf(emptySet<String>()) }

    // 启用功能状态相关
    var enabledFeatures by remember { mutableStateOf(emptyList<SuSFSManager.EnabledFeature>()) }
    var isLoadingFeatures by remember { mutableStateOf(false) }

    // 应用列表相关状态
    var installedApps by remember { mutableStateOf(emptyList<SuSFSManager.AppInfo>()) }

    // 对话框状态
    var showAddPathDialog by remember { mutableStateOf(false) }
    var showAddLoopPathDialog by remember { mutableStateOf(false) }
    var showAddAppPathDialog by remember { mutableStateOf(false) }
    var showAddMountDialog by remember { mutableStateOf(false) }
    var showAddUmountDialog by remember { mutableStateOf(false) }
    var showRunUmountDialog by remember { mutableStateOf(false) }
    var showAddKstatStaticallyDialog by remember { mutableStateOf(false) }
    var showAddKstatDialog by remember { mutableStateOf(false) }

    // 编辑状态
    var editingPath by remember { mutableStateOf<String?>(null) }
    var editingLoopPath by remember { mutableStateOf<String?>(null) }
    var editingMount by remember { mutableStateOf<String?>(null) }
    var editingUmount by remember { mutableStateOf<String?>(null) }
    var editingKstatConfig by remember { mutableStateOf<String?>(null) }
    var editingKstatPath by remember { mutableStateOf<String?>(null) }

    // 重置确认对话框状态
    var showResetPathsDialog by remember { mutableStateOf(false) }
    var showResetLoopPathsDialog by remember { mutableStateOf(false) }
    var showResetMountsDialog by remember { mutableStateOf(false) }
    var showResetUmountsDialog by remember { mutableStateOf(false) }
    var showResetKstatDialog by remember { mutableStateOf(false) }

    // 备份还原相关状态
    var showBackupDialog by remember { mutableStateOf(false) }
    var showRestoreDialog by remember { mutableStateOf(false) }
    var showRestoreConfirmDialog by remember { mutableStateOf(false) }
    var selectedBackupFile by remember { mutableStateOf<String?>(null) }
    var backupInfo by remember { mutableStateOf<SuSFSManager.BackupData?>(null) }

    var isNavigating by remember { mutableStateOf(false) }

    val allTabs = SuSFSTab.getAllTabs(isSusVersion158(), isSusVersion159())

    // 实时判断是否可以启用开机自启动
    val canEnableAutoStart by remember {
        derivedStateOf {
            SuSFSManager.hasConfigurationForAutoStart(context)
        }
    }

    // 文件选择器
    val backupFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        uri?.let { fileUri ->
            val fileName = SuSFSManager.getDefaultBackupFileName()
            val tempFile = File(context.cacheDir, fileName)
            coroutineScope.launch {
                isLoading = true
                val success = SuSFSManager.createBackup(context, tempFile.absolutePath)
                if (success) {
                    try {
                        context.contentResolver.openOutputStream(fileUri)?.use { outputStream ->
                            tempFile.inputStream().use { inputStream ->
                                inputStream.copyTo(outputStream)
                            }
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                    tempFile.delete()
                }
                isLoading = false
                showBackupDialog = false
            }
        }
    }

    val restoreFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { fileUri ->
            coroutineScope.launch {
                try {
                    val tempFile = File(context.cacheDir, "temp_restore.susfs_backup")
                    context.contentResolver.openInputStream(fileUri)?.use { inputStream ->
                        tempFile.outputStream().use { outputStream ->
                            inputStream.copyTo(outputStream)
                        }
                    }

                    // 验证备份文件
                    val backup = SuSFSManager.validateBackupFile(tempFile.absolutePath)
                    if (backup != null) {
                        selectedBackupFile = tempFile.absolutePath
                        backupInfo = backup
                        showRestoreConfirmDialog = true
                    }
                    tempFile.deleteOnExit()
                } catch (e: Exception) {
                    e.printStackTrace()
                }
                showRestoreDialog = false
            }
        }
    }

    // 加载启用功能状态
    fun loadEnabledFeatures() {
        coroutineScope.launch {
            isLoadingFeatures = true
            enabledFeatures = SuSFSManager.getEnabledFeatures(context)
            isLoadingFeatures = false
        }
    }

    // 加载应用列表
    fun loadInstalledApps() {
        coroutineScope.launch {
            installedApps = SuSFSManager.getInstalledApps()
        }
    }

    // 加载槽位信息
    fun loadSlotInfo() {
        coroutineScope.launch {
            isLoadingSlotInfo = true
            slotInfoList = SuSFSManager.getCurrentSlotInfo()
            currentActiveSlot = SuSFSManager.getCurrentActiveSlot()
            isLoadingSlotInfo = false
        }
    }

    // 加载当前配置
    LaunchedEffect(Unit) {
        unameValue = SuSFSManager.getUnameValue(context)
        buildTimeValue = SuSFSManager.getBuildTimeValue(context)
        autoStartEnabled = SuSFSManager.isAutoStartEnabled(context)
        executeInPostFsData = SuSFSManager.getExecuteInPostFsData(context)
        susPaths = SuSFSManager.getSusPaths(context)
        susLoopPaths = SuSFSManager.getSusLoopPaths(context)
        susMounts = SuSFSManager.getSusMounts(context)
        tryUmounts = SuSFSManager.getTryUmounts(context)
        androidDataPath = SuSFSManager.getAndroidDataPath(context)
        sdcardPath = SuSFSManager.getSdcardPath(context)
        kstatConfigs = SuSFSManager.getKstatConfigs(context)
        addKstatPaths = SuSFSManager.getAddKstatPaths(context)
        hideSusMountsForAllProcs = SuSFSManager.getHideSusMountsForAllProcs(context)
        enableHideBl = SuSFSManager.getEnableHideBl(context)
        enableCleanupResidue = SuSFSManager.getEnableCleanupResidue(context)
        umountForZygoteIsoService = SuSFSManager.getUmountForZygoteIsoService(context)

        loadSlotInfo()
    }

    // 当切换到启用功能状态标签页时加载数据
    LaunchedEffect(selectedTab) {
        if (selectedTab == SuSFSTab.ENABLED_FEATURES) {
            loadEnabledFeatures()
        }
    }

    // 当配置变化时，自动调整开机自启动状态
    LaunchedEffect(canEnableAutoStart) {
        if (!canEnableAutoStart && autoStartEnabled) {
            autoStartEnabled = false
            SuSFSManager.configureAutoStart(context, false)
        }
    }

    // 备份对话框
    if (showBackupDialog) {
        AlertDialog(
            onDismissRequest = { showBackupDialog = false },
            title = {
                Text(
                    text = stringResource(R.string.susfs_backup_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Text(stringResource(R.string.susfs_backup_description))
            },
            confirmButton = {
                Button(
                    onClick = {
                        val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
                        val timestamp = dateFormat.format(Date())
                        backupFileLauncher.launch("SuSFS_Config_$timestamp.susfs_backup")
                    },
                    enabled = !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_backup_create))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showBackupDialog = false },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }

    // 还原对话框
    if (showRestoreDialog) {
        AlertDialog(
            onDismissRequest = { showRestoreDialog = false },
            title = {
                Text(
                    text = stringResource(R.string.susfs_restore_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Text(stringResource(R.string.susfs_restore_description))
            },
            confirmButton = {
                Button(
                    onClick = {
                        restoreFileLauncher.launch(arrayOf("application/json", "*/*"))
                    },
                    enabled = !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_restore_select_file))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showRestoreDialog = false },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }

    // 还原确认对话框
    if (showRestoreConfirmDialog && backupInfo != null) {
        AlertDialog(
            onDismissRequest = {
                showRestoreConfirmDialog = false
                selectedBackupFile = null
                backupInfo = null
            },
            title = {
                Text(
                    text = stringResource(R.string.susfs_restore_confirm_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_restore_confirm_description))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                            Text(
                                text = stringResource(R.string.susfs_backup_info_date,
                                    dateFormat.format(Date(backupInfo!!.timestamp))),
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                text = stringResource(R.string.susfs_backup_info_device, backupInfo!!.deviceInfo),
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                text = stringResource(R.string.susfs_backup_info_version, backupInfo!!.version),
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        selectedBackupFile?.let { filePath ->
                            coroutineScope.launch {
                                isLoading = true
                                val success = SuSFSManager.restoreFromBackup(context, filePath)
                                if (success) {
                                    // 重新加载所有配置
                                    unameValue = SuSFSManager.getUnameValue(context)
                                    buildTimeValue = SuSFSManager.getBuildTimeValue(context)
                                    autoStartEnabled = SuSFSManager.isAutoStartEnabled(context)
                                    executeInPostFsData = SuSFSManager.getExecuteInPostFsData(context)
                                    susPaths = SuSFSManager.getSusPaths(context)
                                    susLoopPaths = SuSFSManager.getSusLoopPaths(context)
                                    susMounts = SuSFSManager.getSusMounts(context)
                                    tryUmounts = SuSFSManager.getTryUmounts(context)
                                    androidDataPath = SuSFSManager.getAndroidDataPath(context)
                                    sdcardPath = SuSFSManager.getSdcardPath(context)
                                    kstatConfigs = SuSFSManager.getKstatConfigs(context)
                                    addKstatPaths = SuSFSManager.getAddKstatPaths(context)
                                    hideSusMountsForAllProcs = SuSFSManager.getHideSusMountsForAllProcs(context)
                                    enableHideBl = SuSFSManager.getEnableHideBl(context)
                                    enableCleanupResidue = SuSFSManager.getEnableCleanupResidue(context)
                                    umountForZygoteIsoService = SuSFSManager.getUmountForZygoteIsoService(context)
                                }
                                isLoading = false
                                showRestoreConfirmDialog = false
                                selectedBackupFile = null
                                backupInfo = null
                            }
                        }
                    },
                    enabled = !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_restore_confirm))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showRestoreConfirmDialog = false
                        selectedBackupFile = null
                        backupInfo = null
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }

    // 槽位信息对话框
    SlotInfoDialog(
        showDialog = showSlotInfoDialog,
        onDismiss = { showSlotInfoDialog = false },
        slotInfoList = slotInfoList,
        currentActiveSlot = currentActiveSlot,
        isLoadingSlotInfo = isLoadingSlotInfo,
        onRefresh = { loadSlotInfo() },
        onUseUname = { uname ->
            unameValue = uname
            showSlotInfoDialog = false
        },
        onUseBuildTime = { buildTime ->
            buildTimeValue = buildTime
            showSlotInfoDialog = false
        }
    )

    // 各种对话框
    AddPathDialog(
        showDialog = showAddPathDialog,
        onDismiss = {
            showAddPathDialog = false
            editingPath = null
        },
        onConfirm = { path ->
            coroutineScope.launch {
                isLoading = true
                val success = if (editingPath != null) {
                    SuSFSManager.editSusPath(context, editingPath!!, path)
                } else {
                    SuSFSManager.addSusPath(context, path)
                }
                if (success) {
                    susPaths = SuSFSManager.getSusPaths(context)
                }
                isLoading = false
                showAddPathDialog = false
                editingPath = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingPath != null) R.string.susfs_edit_sus_path else R.string.susfs_add_sus_path,
        labelRes = R.string.susfs_path_label,
        placeholderRes = R.string.susfs_path_placeholder,
        initialValue = editingPath ?: ""
    )

    AddPathDialog(
        showDialog = showAddLoopPathDialog,
        onDismiss = {
            showAddLoopPathDialog = false
            editingLoopPath = null
        },
        onConfirm = { path ->
            coroutineScope.launch {
                isLoading = true
                val success = if (editingLoopPath != null) {
                    SuSFSManager.editSusLoopPath(context, editingLoopPath!!, path)
                } else {
                    SuSFSManager.addSusLoopPath(context, path)
                }
                if (success) {
                    susLoopPaths = SuSFSManager.getSusLoopPaths(context)
                }
                isLoading = false
                showAddLoopPathDialog = false
                editingLoopPath = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingLoopPath != null) R.string.susfs_edit_sus_loop_path else R.string.susfs_add_sus_loop_path,
        labelRes = R.string.susfs_loop_path_label,
        placeholderRes = R.string.susfs_loop_path_placeholder,
        initialValue = editingLoopPath ?: ""
    )

    AddAppPathDialog(
        showDialog = showAddAppPathDialog,
        onDismiss = { showAddAppPathDialog = false },
        onConfirm = { packageNames ->
            coroutineScope.launch {
                isLoading = true
                var successCount = 0
                packageNames.forEach { packageName ->
                    if (SuSFSManager.addAppPaths(context, packageName)) {
                        successCount++
                    }
                }
                if (successCount > 0) {
                    susPaths = SuSFSManager.getSusPaths(context)
                }
                isLoading = false
                showAddAppPathDialog = false
            }
        },
        isLoading = isLoading,
        apps = installedApps,
        onLoadApps = { loadInstalledApps() },
        existingSusPaths = susPaths
    )

    AddPathDialog(
        showDialog = showAddMountDialog,
        onDismiss = {
            showAddMountDialog = false
            editingMount = null
        },
        onConfirm = { mount ->
            coroutineScope.launch {
                isLoading = true
                val success = if (editingMount != null) {
                    SuSFSManager.editSusMount(context, editingMount!!, mount)
                } else {
                    SuSFSManager.addSusMount(context, mount)
                }
                if (success) {
                    susMounts = SuSFSManager.getSusMounts(context)
                }
                isLoading = false
                showAddMountDialog = false
                editingMount = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingMount != null) R.string.susfs_edit_sus_mount else R.string.susfs_add_sus_mount,
        labelRes = R.string.susfs_mount_path_label,
        placeholderRes = R.string.susfs_path_placeholder,
        initialValue = editingMount ?: ""
    )

    AddTryUmountDialog(
        showDialog = showAddUmountDialog,
        onDismiss = {
            showAddUmountDialog = false
            editingUmount = null
        },
        onConfirm = { path, mode ->
            coroutineScope.launch {
                isLoading = true
                val success = if (editingUmount != null) {
                    SuSFSManager.editTryUmount(context, editingUmount!!, path, mode)
                } else {
                    SuSFSManager.addTryUmount(context, path, mode)
                }
                if (success) {
                    tryUmounts = SuSFSManager.getTryUmounts(context)
                }
                isLoading = false
                showAddUmountDialog = false
                editingUmount = null
            }
        },
        isLoading = isLoading,
        initialPath = editingUmount?.split("|")?.get(0) ?: "",
        initialMode = editingUmount?.split("|")?.get(1)?.toIntOrNull() ?: 0
    )

    AddKstatStaticallyDialog(
        showDialog = showAddKstatStaticallyDialog,
        onDismiss = {
            showAddKstatStaticallyDialog = false
            editingKstatConfig = null
        },
        onConfirm = { path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize ->
            coroutineScope.launch {
                isLoading = true
                val success = if (editingKstatConfig != null) {
                    SuSFSManager.editKstatConfig(
                        context, editingKstatConfig!!, path, ino, dev, nlink, size, atime, atimeNsec,
                        mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize
                    )
                } else {
                    SuSFSManager.addKstatStatically(
                        context, path, ino, dev, nlink, size, atime, atimeNsec,
                        mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize
                    )
                }
                if (success) {
                    kstatConfigs = SuSFSManager.getKstatConfigs(context)
                }
                isLoading = false
                showAddKstatStaticallyDialog = false
                editingKstatConfig = null
            }
        },
        isLoading = isLoading,
        initialConfig = editingKstatConfig ?: ""
    )

    AddPathDialog(
        showDialog = showAddKstatDialog,
        onDismiss = {
            showAddKstatDialog = false
            editingKstatPath = null
        },
        onConfirm = { path ->
            coroutineScope.launch {
                isLoading = true
                val success = if (editingKstatPath != null) {
                    SuSFSManager.editAddKstat(context, editingKstatPath!!, path)
                } else {
                    SuSFSManager.addKstat(context, path)
                }
                if (success) {
                    addKstatPaths = SuSFSManager.getAddKstatPaths(context)
                }
                isLoading = false
                showAddKstatDialog = false
                editingKstatPath = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingKstatPath != null) R.string.edit_kstat_path_title else R.string.add_kstat_path_title,
        labelRes = R.string.file_or_directory_path_label,
        placeholderRes = R.string.susfs_path_placeholder,
        initialValue = editingKstatPath ?: ""
    )

    // 确认对话框
    ConfirmDialog(
        showDialog = showRunUmountDialog,
        onDismiss = { showRunUmountDialog = false },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.runTryUmount(context)
                isLoading = false
                showRunUmountDialog = false
            }
        },
        titleRes = R.string.susfs_run_umount_confirm_title,
        messageRes = R.string.susfs_run_umount_confirm_message,
        isLoading = isLoading
    )

    ConfirmDialog(
        showDialog = showConfirmReset,
        onDismiss = { showConfirmReset = false },
        onConfirm = {
            showConfirmReset = false
            coroutineScope.launch {
                isLoading = true
                if (SuSFSManager.resetToDefault(context)) {
                    unameValue = "default"
                    buildTimeValue = "default"
                    autoStartEnabled = false
                }
                isLoading = false
            }
        },
        titleRes = R.string.susfs_reset_confirm_title,
        messageRes = R.string.susfs_reset_confirm_title,
        isLoading = isLoading,
        isDestructive = true
    )

    // 重置对话框
    ConfirmDialog(
        showDialog = showResetPathsDialog,
        onDismiss = { showResetPathsDialog = false },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveSusPaths(context, emptySet())
                susPaths = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
                showResetPathsDialog = false
            }
        },
        titleRes = R.string.susfs_reset_paths_title,
        messageRes = R.string.susfs_reset_paths_message,
        isLoading = isLoading,
        isDestructive = true
    )

    ConfirmDialog(
        showDialog = showResetLoopPathsDialog,
        onDismiss = { showResetLoopPathsDialog = false },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveSusLoopPaths(context, emptySet())
                susLoopPaths = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
                showResetLoopPathsDialog = false
            }
        },
        titleRes = R.string.susfs_reset_loop_paths_title,
        messageRes = R.string.susfs_reset_loop_paths_message,
        isLoading = isLoading,
        isDestructive = true
    )

    ConfirmDialog(
        showDialog = showResetMountsDialog,
        onDismiss = { showResetMountsDialog = false },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveSusMounts(context, emptySet())
                susMounts = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
                showResetMountsDialog = false
            }
        },
        titleRes = R.string.susfs_reset_mounts_title,
        messageRes = R.string.susfs_reset_mounts_message,
        isLoading = isLoading,
        isDestructive = true
    )

    ConfirmDialog(
        showDialog = showResetUmountsDialog,
        onDismiss = { showResetUmountsDialog = false },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveTryUmounts(context, emptySet())
                tryUmounts = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
                showResetUmountsDialog = false
            }
        },
        titleRes = R.string.susfs_reset_umounts_title,
        messageRes = R.string.susfs_reset_umounts_message,
        isLoading = isLoading,
        isDestructive = true
    )

    ConfirmDialog(
        showDialog = showResetKstatDialog,
        onDismiss = { showResetKstatDialog = false },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveKstatConfigs(context, emptySet())
                SuSFSManager.saveAddKstatPaths(context, emptySet())
                kstatConfigs = emptySet()
                addKstatPaths = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
                showResetKstatDialog = false
            }
        },
        titleRes = R.string.reset_kstat_config_title,
        messageRes = R.string.reset_kstat_config_message,
        isLoading = isLoading,
        isDestructive = true
    )

    // 主界面布局
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.susfs_config_title),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = {
                        if (!isNavigating) {
                            isNavigating = true
                            navigator.popBackStack()
                        }
                    }) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = CardConfig.cardAlpha),
                    scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = CardConfig.cardAlpha)
                ),
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
            )
        },
        bottomBar = {
            // 统一的底部按钮栏
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color.Transparent,
                shadowElevation = 0.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    when (selectedTab) {
                        SuSFSTab.BASIC_SETTINGS -> {
                            // 应用按钮
                            Button(
                                onClick = {
                                    if (unameValue.isNotBlank() || buildTimeValue.isNotBlank()) {
                                        coroutineScope.launch {
                                            isLoading = true
                                            val finalUnameValue = unameValue.trim().ifBlank { "default" }
                                            val finalBuildTimeValue = buildTimeValue.trim().ifBlank { "default" }
                                            val success = SuSFSManager.setUname(context, finalUnameValue, finalBuildTimeValue)
                                            if (success) {
                                                SuSFSManager.saveExecuteInPostFsData(context, executeInPostFsData)
                                                SuSFSManager.saveEnableHideBl(context, enableHideBl)
                                                SuSFSManager.saveEnableCleanupResidue(context, enableCleanupResidue)
                                            }
                                            isLoading = false
                                        }
                                    }
                                },
                                enabled = !isLoading && (unameValue.isNotBlank() || buildTimeValue.isNotBlank()),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(40.dp)
                            ) {
                                Text(
                                    stringResource(R.string.susfs_apply),
                                    fontWeight = FontWeight.Medium
                                )
                            }

                            // 重置按钮
                            OutlinedButton(
                                onClick = { showConfirmReset = true },
                                enabled = !isLoading,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.susfs_reset_to_default),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.SUS_PATHS -> {
                            OutlinedButton(
                                onClick = { showResetPathsDialog = true },
                                enabled = !isLoading && susPaths.isNotEmpty(),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.susfs_reset_paths_title),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.SUS_LOOP_PATHS -> {
                            OutlinedButton(
                                onClick = { showResetLoopPathsDialog = true },
                                enabled = !isLoading && susLoopPaths.isNotEmpty(),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.susfs_reset_loop_paths_title),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.SUS_MOUNTS -> {
                            OutlinedButton(
                                onClick = { showResetMountsDialog = true },
                                enabled = !isLoading && susMounts.isNotEmpty(),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.susfs_reset_mounts_title),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.TRY_UMOUNT -> {
                            OutlinedButton(
                                onClick = { showResetUmountsDialog = true },
                                enabled = !isLoading && tryUmounts.isNotEmpty(),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.susfs_reset_umounts_title),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.KSTAT_CONFIG -> {
                            OutlinedButton(
                                onClick = { showResetKstatDialog = true },
                                enabled = !isLoading && (kstatConfigs.isNotEmpty() || addKstatPaths.isNotEmpty()),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.reset_kstat_config_title),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.PATH_SETTINGS -> {
                            OutlinedButton(
                                onClick = {
                                    androidDataPath = "/sdcard/Android/data"
                                    sdcardPath = "/sdcard"
                                    coroutineScope.launch {
                                        isLoading = true
                                        SuSFSManager.setAndroidDataPath(context, androidDataPath)
                                        SuSFSManager.setSdcardPath(context, sdcardPath)
                                        isLoading = false
                                    }
                                },
                                enabled = !isLoading,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.RestoreFromTrash,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.susfs_reset_path_title),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        SuSFSTab.ENABLED_FEATURES -> {
                            Button(
                                onClick = { loadEnabledFeatures() },
                                enabled = !isLoadingFeatures,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(40.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Refresh,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    stringResource(R.string.refresh),
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                }
            }
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 12.dp)
        ) {
            // 标签页
            ScrollableTabRow(
                selectedTabIndex = allTabs.indexOf(selectedTab),
                edgePadding = 0.dp,
                modifier = Modifier.fillMaxWidth(),
                containerColor = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface
            ) {
                allTabs.forEachIndexed { index, tab ->
                    Tab(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        text = {
                            Text(
                                text = stringResource(tab.displayNameRes),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                fontSize = 13.sp,
                                fontWeight = if (selectedTab == tab) FontWeight.Bold else FontWeight.Normal
                            )
                        },
                        modifier = Modifier.padding(horizontal = 2.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // 标签页内容
            Box(
                modifier = Modifier.fillMaxSize()
            ) {
                when (selectedTab) {
                    SuSFSTab.BASIC_SETTINGS -> {
                        BasicSettingsContent(
                            unameValue = unameValue,
                            onUnameValueChange = { unameValue = it },
                            buildTimeValue = buildTimeValue,
                            onBuildTimeValueChange = { buildTimeValue = it },
                            executeInPostFsData = executeInPostFsData,
                            onExecuteInPostFsDataChange = { executeInPostFsData = it },
                            autoStartEnabled = autoStartEnabled,
                            canEnableAutoStart = canEnableAutoStart,
                            isLoading = isLoading,
                            onAutoStartToggle = { enabled ->
                                if (canEnableAutoStart) {
                                    coroutineScope.launch {
                                        isLoading = true
                                        if (SuSFSManager.configureAutoStart(context, enabled)) {
                                            autoStartEnabled = enabled
                                        }
                                        isLoading = false
                                    }
                                }
                            },
                            onShowSlotInfo = { showSlotInfoDialog = true },
                            context = context,
                            onShowBackupDialog = { showBackupDialog = true },
                            onShowRestoreDialog = { showRestoreDialog = true },
                            enableHideBl = enableHideBl,
                            onEnableHideBlChange = { enabled ->
                                enableHideBl = enabled
                                SuSFSManager.saveEnableHideBl(context, enabled)
                                if (SuSFSManager.isAutoStartEnabled(context)) {
                                    coroutineScope.launch {
                                        SuSFSManager.configureAutoStart(context, true)
                                    }
                                }
                            },
                            enableCleanupResidue = enableCleanupResidue,
                            onEnableCleanupResidueChange = { enabled ->
                                enableCleanupResidue = enabled
                                SuSFSManager.saveEnableCleanupResidue(context, enabled)
                                if (SuSFSManager.isAutoStartEnabled(context)) {
                                    coroutineScope.launch {
                                        SuSFSManager.configureAutoStart(context, true)
                                    }
                                }
                            }
                        )
                    }
                    SuSFSTab.SUS_PATHS -> {
                        SusPathsContent(
                            susPaths = susPaths,
                            isLoading = isLoading,
                            onAddPath = { showAddPathDialog = true },
                            onAddAppPath = { showAddAppPathDialog = true },
                            onRemovePath = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeSusPath(context, path)) {
                                        susPaths = SuSFSManager.getSusPaths(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditPath = { path ->
                                editingPath = path
                                showAddPathDialog = true
                            },
                            forceRefreshApps = selectedTab == SuSFSTab.SUS_PATHS
                        )
                    }
                    SuSFSTab.SUS_LOOP_PATHS -> {
                        SusLoopPathsContent(
                            susLoopPaths = susLoopPaths,
                            isLoading = isLoading,
                            onAddLoopPath = { showAddLoopPathDialog = true },
                            onRemoveLoopPath = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeSusLoopPath(context, path)) {
                                        susLoopPaths = SuSFSManager.getSusLoopPaths(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditLoopPath = { path ->
                                editingLoopPath = path
                                showAddLoopPathDialog = true
                            }
                        )
                    }
                    SuSFSTab.SUS_MOUNTS -> {
                        val isSusVersion158 = remember { isSusVersion158() }

                        SusMountsContent(
                            susMounts = susMounts,
                            hideSusMountsForAllProcs = hideSusMountsForAllProcs,
                            isSusVersion158 = isSusVersion158,
                            isLoading = isLoading,
                            onAddMount = { showAddMountDialog = true },
                            onRemoveMount = { mount ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeSusMount(context, mount)) {
                                        susMounts = SuSFSManager.getSusMounts(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditMount = { mount ->
                                editingMount = mount
                                showAddMountDialog = true
                            },
                            onToggleHideSusMountsForAllProcs = { hideForAll ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.setHideSusMountsForAllProcs(context, hideForAll)) {
                                        hideSusMountsForAllProcs = hideForAll
                                    }
                                    isLoading = false
                                }
                            }
                        )
                    }

                    SuSFSTab.TRY_UMOUNT -> {
                        TryUmountContent(
                            tryUmounts = tryUmounts,
                            umountForZygoteIsoService = umountForZygoteIsoService,
                            isLoading = isLoading,
                            onAddUmount = { showAddUmountDialog = true },
                            onRunUmount = { showRunUmountDialog = true },
                            onRemoveUmount = { umountEntry ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeTryUmount(context, umountEntry)) {
                                        tryUmounts = SuSFSManager.getTryUmounts(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditUmount = { umountEntry ->
                                editingUmount = umountEntry
                                showAddUmountDialog = true
                            },
                            onToggleUmountForZygoteIsoService = { enabled ->
                                coroutineScope.launch {
                                    isLoading = true
                                    val success = SuSFSManager.setUmountForZygoteIsoService(context, enabled)
                                    if (success) {
                                        umountForZygoteIsoService = enabled
                                    }
                                    isLoading = false
                                }
                            }
                        )
                    }

                    SuSFSTab.KSTAT_CONFIG -> {
                        KstatConfigContent(
                            kstatConfigs = kstatConfigs,
                            addKstatPaths = addKstatPaths,
                            isLoading = isLoading,
                            onAddKstatStatically = { showAddKstatStaticallyDialog = true },
                            onAddKstat = { showAddKstatDialog = true },
                            onRemoveKstatConfig = { config ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeKstatConfig(context, config)) {
                                        kstatConfigs = SuSFSManager.getKstatConfigs(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditKstatConfig = { config ->
                                editingKstatConfig = config
                                showAddKstatStaticallyDialog = true
                            },
                            onRemoveAddKstat = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeAddKstat(context, path)) {
                                        addKstatPaths = SuSFSManager.getAddKstatPaths(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditAddKstat = { path ->
                                editingKstatPath = path
                                showAddKstatDialog = true
                            },
                            onUpdateKstat = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.updateKstat(context, path)
                                    isLoading = false
                                }
                            },
                            onUpdateKstatFullClone = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.updateKstatFullClone(context, path)
                                    isLoading = false
                                }
                            }
                        )
                    }
                    SuSFSTab.PATH_SETTINGS -> {
                        PathSettingsContent(
                            androidDataPath = androidDataPath,
                            onAndroidDataPathChange = { androidDataPath = it },
                            sdcardPath = sdcardPath,
                            onSdcardPathChange = { sdcardPath = it },
                            isLoading = isLoading,
                            onSetAndroidDataPath = {
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.setAndroidDataPath(context, androidDataPath.trim())
                                    isLoading = false
                                }
                            },
                            onSetSdcardPath = {
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.setSdcardPath(context, sdcardPath.trim())
                                    isLoading = false
                                }
                            }
                        )
                    }
                    SuSFSTab.ENABLED_FEATURES -> {
                        EnabledFeaturesContent(
                            enabledFeatures = enabledFeatures,
                            onRefresh = { loadEnabledFeatures() }
                        )
                    }
                }
            }
        }
    }
}

/**
 * 基本设置内容组件
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BasicSettingsContent(
    unameValue: String,
    onUnameValueChange: (String) -> Unit,
    buildTimeValue: String,
    onBuildTimeValueChange: (String) -> Unit,
    executeInPostFsData: Boolean,
    onExecuteInPostFsDataChange: (Boolean) -> Unit,
    autoStartEnabled: Boolean,
    canEnableAutoStart: Boolean,
    isLoading: Boolean,
    onAutoStartToggle: (Boolean) -> Unit,
    onShowSlotInfo: () -> Unit,
    context: android.content.Context,
    onShowBackupDialog: () -> Unit,
    onShowRestoreDialog: () -> Unit,
    enableHideBl: Boolean,
    onEnableHideBlChange: (Boolean) -> Unit,
    enableCleanupResidue: Boolean,
    onEnableCleanupResidueChange: (Boolean) -> Unit
) {
    var scriptLocationExpanded by remember { mutableStateOf(false) }
    val isAbDevice = isAbDevice()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // 说明卡片
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Text(
                    text = stringResource(R.string.susfs_config_description),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.susfs_config_description_text),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 16.sp
                )
            }
        }

        // Uname输入框
        OutlinedTextField(
            value = unameValue,
            onValueChange = onUnameValueChange,
            label = { Text(stringResource(R.string.susfs_uname_label)) },
            placeholder = { Text(stringResource(R.string.susfs_uname_placeholder)) },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            shape = RoundedCornerShape(8.dp)
        )

        // 构建时间伪装输入框
        OutlinedTextField(
            value = buildTimeValue,
            onValueChange = onBuildTimeValueChange,
            label = { Text(stringResource(R.string.susfs_build_time_label)) },
            placeholder = { Text(stringResource(R.string.susfs_build_time_placeholder)) },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            shape = RoundedCornerShape(8.dp)
        )

        // 执行位置选择
        ExposedDropdownMenuBox(
            expanded = scriptLocationExpanded,
            onExpandedChange = { scriptLocationExpanded = !scriptLocationExpanded }
        ) {
            OutlinedTextField(
                value = if (executeInPostFsData)
                    stringResource(R.string.susfs_execution_location_post_fs_data)
                else
                    stringResource(R.string.susfs_execution_location_service),
                onValueChange = { },
                readOnly = true,
                label = { Text(stringResource(R.string.susfs_execution_location_label)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = scriptLocationExpanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(MenuAnchorType.PrimaryEditable, true),
                shape = RoundedCornerShape(8.dp),
                enabled = !isLoading
            )
            ExposedDropdownMenu(
                expanded = scriptLocationExpanded,
                onDismissRequest = { scriptLocationExpanded = false }
            ) {
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(stringResource(R.string.susfs_execution_location_service))
                            Text(
                                stringResource(R.string.susfs_execution_location_service_description),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    },
                    onClick = {
                        onExecuteInPostFsDataChange(false)
                        scriptLocationExpanded = false
                    }
                )
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(stringResource(R.string.susfs_execution_location_post_fs_data))
                            Text(
                                stringResource(R.string.susfs_execution_location_post_fs_data_description),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    },
                    onClick = {
                        onExecuteInPostFsDataChange(true)
                        scriptLocationExpanded = false
                    }
                )
            }
        }

        // 当前值显示
        Column(
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = stringResource(R.string.susfs_current_value, SuSFSManager.getUnameValue(context)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = stringResource(R.string.susfs_current_build_time, SuSFSManager.getBuildTimeValue(context)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = stringResource(R.string.susfs_current_execution_location, if (SuSFSManager.getExecuteInPostFsData(context)) "Post-FS-Data" else "Service"),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // 开机自启动开关
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = if (canEnableAutoStart) {
                    MaterialTheme.colorScheme.surface
                } else {
                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                }
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.AutoMode,
                            contentDescription = null,
                            tint = if (canEnableAutoStart) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            },
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.susfs_autostart_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            color = if (canEnableAutoStart) {
                                MaterialTheme.colorScheme.onSurface
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            }
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (canEnableAutoStart) {
                            stringResource(R.string.susfs_autostart_description)
                        } else {
                            stringResource(R.string.susfs_autostart_requirement)
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(
                            alpha = if (canEnableAutoStart) 1f else 0.5f
                        ),
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = autoStartEnabled,
                    onCheckedChange = onAutoStartToggle,
                    enabled = !isLoading && canEnableAutoStart
                )
            }
        }

        // 隐藏BL脚本开关
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.hide_bl_script),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = stringResource(R.string.hide_bl_script_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = enableHideBl,
                    onCheckedChange = onEnableHideBlChange,
                    enabled = !isLoading
                )
            }
        }

        // 清理残留脚本开关
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.CleaningServices,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.cleanup_residue),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = stringResource(R.string.cleanup_residue_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = enableCleanupResidue,
                    onCheckedChange = onEnableCleanupResidueChange,
                    enabled = !isLoading
                )
            }
        }

        // 槽位信息按钮
        if (isAbDevice) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.susfs_slot_info_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Text(
                        text = stringResource(R.string.susfs_slot_info_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 14.sp
                    )

                    OutlinedButton(
                        onClick = onShowSlotInfo,
                        enabled = !isLoading,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Storage,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            stringResource(R.string.susfs_slot_info_title),
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 备份按钮
            OutlinedButton(
                onClick = onShowBackupDialog,
                enabled = !isLoading,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .weight(1f)
                    .height(40.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Backup,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    stringResource(R.string.susfs_backup_title),
                    fontWeight = FontWeight.Medium
                )
            }
            // 还原按钮
            OutlinedButton(
                onClick = onShowRestoreDialog,
                enabled = !isLoading,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .weight(1f)
                    .height(40.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Restore,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    stringResource(R.string.susfs_restore_title),
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

/**
 * 槽位信息对话框
 */
@Composable
private fun SlotInfoDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    slotInfoList: List<SuSFSManager.SlotInfo>,
    currentActiveSlot: String,
    isLoadingSlotInfo: Boolean,
    onRefresh: () -> Unit,
    onUseUname: (String) -> Unit,
    onUseBuildTime: (String) -> Unit
) {
    val isAbDevice = isAbDevice()

    if (showDialog && isAbDevice) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    text = stringResource(R.string.susfs_slot_info_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.susfs_current_active_slot, currentActiveSlot),
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.primary
                    )

                    if (slotInfoList.isNotEmpty()) {
                        slotInfoList.forEach { slotInfo ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = if (slotInfo.slotName == currentActiveSlot) {
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                                    }
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Storage,
                                            contentDescription = null,
                                            tint = if (slotInfo.slotName == currentActiveSlot) {
                                                MaterialTheme.colorScheme.primary
                                            } else {
                                                MaterialTheme.colorScheme.onSurfaceVariant
                                            },
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = slotInfo.slotName,
                                            style = MaterialTheme.typography.titleMedium,
                                            fontWeight = FontWeight.Bold,
                                            color = if (slotInfo.slotName == currentActiveSlot) {
                                                MaterialTheme.colorScheme.primary
                                            } else {
                                                MaterialTheme.colorScheme.onSurface
                                            }
                                        )
                                        if (slotInfo.slotName == currentActiveSlot) {
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Surface(
                                                shape = RoundedCornerShape(4.dp),
                                                color = MaterialTheme.colorScheme.primary
                                            ) {
                                                Text(
                                                    text = stringResource(R.string.susfs_slot_current_badge),
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.onPrimary,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                        }
                                    }
                                    Text(
                                        text = stringResource(R.string.susfs_slot_uname, slotInfo.uname),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Text(
                                        text = stringResource(R.string.susfs_slot_build_time, slotInfo.buildTime),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Button(
                                            onClick = { onUseUname(slotInfo.uname) },
                                            modifier = Modifier.weight(1f),
                                            shape = RoundedCornerShape(6.dp)
                                        ) {
                                            Text(stringResource(R.string.susfs_slot_use_uname), fontSize = 12.sp)
                                        }
                                        Button(
                                            onClick = { onUseBuildTime(slotInfo.buildTime) },
                                            modifier = Modifier.weight(1f),
                                            shape = RoundedCornerShape(6.dp)
                                        ) {
                                            Text(stringResource(R.string.susfs_slot_use_build_time), fontSize = 12.sp)
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        Text(
                            text = stringResource(R.string.susfs_slot_info_unavailable),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = onRefresh,
                    enabled = !isLoadingSlotInfo,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.refresh))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = onDismiss,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.close))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }
}