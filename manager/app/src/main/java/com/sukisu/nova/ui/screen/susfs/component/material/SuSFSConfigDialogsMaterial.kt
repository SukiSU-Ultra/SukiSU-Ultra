package com.sukisu.nova.ui.screen.susfs.component.material

import android.content.pm.PackageInfo
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import com.sukisu.nova.ui.screen.susfs.util.AppInfoCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


@Composable
fun AddPathDialogMaterial(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
    isLoading: Boolean,
    titleRes: Int,
    labelRes: Int,
    initialValue: String = ""
) {
    var newPath by remember { mutableStateOf(initialValue) }

    LaunchedEffect(showDialog, initialValue) {
        if (showDialog) {
            newPath = initialValue
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = {
                onDismiss()
                newPath = ""
            },
            title = { Text(stringResource(titleRes)) },
            text = {
                OutlinedTextField(
                    value = newPath,
                    onValueChange = { newPath = it },
                    label = { Text(stringResource(labelRes)) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isLoading,
                    singleLine = true
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (newPath.isNotBlank()) {
                            onConfirm(newPath.trim())
                        }
                    },
                    enabled = newPath.isNotBlank() && !isLoading
                ) {
                    Text(stringResource(if (initialValue.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        newPath = ""
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
fun AddKstatStaticallyDialogMaterial(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, String, String, String, String, String, String, String, String, String, String, String, String) -> Unit,
    isLoading: Boolean,
    initialConfig: String = ""
) {
    var newKstatPath by remember { mutableStateOf("") }
    var newKstatIno by remember { mutableStateOf("") }
    var newKstatDev by remember { mutableStateOf("") }
    var newKstatNlink by remember { mutableStateOf("") }
    var newKstatSize by remember { mutableStateOf("") }
    var newKstatAtime by remember { mutableStateOf("") }
    var newKstatAtimeNsec by remember { mutableStateOf("") }
    var newKstatMtime by remember { mutableStateOf("") }
    var newKstatMtimeNsec by remember { mutableStateOf("") }
    var newKstatCtime by remember { mutableStateOf("") }
    var newKstatCtimeNsec by remember { mutableStateOf("") }
    var newKstatBlocks by remember { mutableStateOf("") }
    var newKstatBlksize by remember { mutableStateOf("") }

    LaunchedEffect(showDialog, initialConfig) {
        if (showDialog && initialConfig.isNotEmpty()) {
            val parts = initialConfig.split("|")
            if (parts.size >= 13) {
                newKstatPath = parts[0]
                newKstatIno = parts[1].takeUnless { it == "default" }.orEmpty()
                newKstatDev = parts[2].takeUnless { it == "default" }.orEmpty()
                newKstatNlink = parts[3].takeUnless { it == "default" }.orEmpty()
                newKstatSize = parts[4].takeUnless { it == "default" }.orEmpty()
                newKstatAtime = parts[5].takeUnless { it == "default" }.orEmpty()
                newKstatAtimeNsec = parts[6].takeUnless { it == "default" }.orEmpty()
                newKstatMtime = parts[7].takeUnless { it == "default" }.orEmpty()
                newKstatMtimeNsec = parts[8].takeUnless { it == "default" }.orEmpty()
                newKstatCtime = parts[9].takeUnless { it == "default" }.orEmpty()
                newKstatCtimeNsec = parts[10].takeUnless { it == "default" }.orEmpty()
                newKstatBlocks = parts[11].takeUnless { it == "default" }.orEmpty()
                newKstatBlksize = parts[12].takeUnless { it == "default" }.orEmpty()
            }
        } else if (showDialog) {
            newKstatPath = ""
            newKstatIno = ""
            newKstatDev = ""
            newKstatNlink = ""
            newKstatSize = ""
            newKstatAtime = ""
            newKstatAtimeNsec = ""
            newKstatMtime = ""
            newKstatMtimeNsec = ""
            newKstatCtime = ""
            newKstatCtimeNsec = ""
            newKstatBlocks = ""
            newKstatBlksize = ""
        }
    }

    val resetFields = {
        newKstatPath = ""
        newKstatIno = ""
        newKstatDev = ""
        newKstatNlink = ""
        newKstatSize = ""
        newKstatAtime = ""
        newKstatAtimeNsec = ""
        newKstatMtime = ""
        newKstatMtimeNsec = ""
        newKstatCtime = ""
        newKstatCtimeNsec = ""
        newKstatBlocks = ""
        newKstatBlksize = ""
    }

    if (showDialog) {
        com.sukisu.nova.ui.component.material.ExpressiveDialog(
            onDismissRequest = {
                onDismiss()
                resetFields()
            },
            title = {
                Text(stringResource(if (initialConfig.isNotEmpty()) R.string.edit_kstat_statically_title else R.string.add_kstat_statically_title))
            },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 500.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedTextField(
                        value = newKstatPath,
                        onValueChange = { newKstatPath = it },
                        label = { Text(stringResource(R.string.file_or_directory_path_label)) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        singleLine = true,
                        shape = MaterialTheme.shapes.large
                    )

                    KstatSectionMaterial(stringResource(R.string.kstat_section_identity)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMaterial("ino", newKstatIno, { newKstatIno = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMaterial("dev", newKstatDev, { newKstatDev = it }, !isLoading, Modifier.weight(1f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMaterial("nlink", newKstatNlink, { newKstatNlink = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMaterial("size", newKstatSize, { newKstatSize = it }, !isLoading, Modifier.weight(1f))
                        }
                    }

                    KstatSectionMaterial(stringResource(R.string.kstat_section_timestamps)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMaterial("atime", newKstatAtime, { newKstatAtime = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMaterial("atime_nsec", newKstatAtimeNsec, { newKstatAtimeNsec = it }, !isLoading, Modifier.weight(1f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMaterial("mtime", newKstatMtime, { newKstatMtime = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMaterial("mtime_nsec", newKstatMtimeNsec, { newKstatMtimeNsec = it }, !isLoading, Modifier.weight(1f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMaterial("ctime", newKstatCtime, { newKstatCtime = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMaterial("ctime_nsec", newKstatCtimeNsec, { newKstatCtimeNsec = it }, !isLoading, Modifier.weight(1f))
                        }
                    }

                    KstatSectionMaterial(stringResource(R.string.kstat_section_storage)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMaterial("blocks", newKstatBlocks, { newKstatBlocks = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMaterial("blksize", newKstatBlksize, { newKstatBlksize = it }, !isLoading, Modifier.weight(1f))
                        }
                    }

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
                    ) {
                        Text(
                            text = stringResource(R.string.hint_use_default_value),
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (newKstatPath.isNotBlank()) {
                            onConfirm(
                                newKstatPath.trim(),
                                newKstatIno.trim().ifBlank { "default" },
                                newKstatDev.trim().ifBlank { "default" },
                                newKstatNlink.trim().ifBlank { "default" },
                                newKstatSize.trim().ifBlank { "default" },
                                newKstatAtime.trim().ifBlank { "default" },
                                newKstatAtimeNsec.trim().ifBlank { "default" },
                                newKstatMtime.trim().ifBlank { "default" },
                                newKstatMtimeNsec.trim().ifBlank { "default" },
                                newKstatCtime.trim().ifBlank { "default" },
                                newKstatCtimeNsec.trim().ifBlank { "default" },
                                newKstatBlocks.trim().ifBlank { "default" },
                                newKstatBlksize.trim().ifBlank { "default" }
                            )
                            resetFields()
                        }
                    },
                    enabled = newKstatPath.isNotBlank() && !isLoading
                ) {
                    Text(stringResource(if (initialConfig.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        resetFields()
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
private fun KstatSectionMaterial(
    title: String,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            content = {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold
                )
                content()
            }
        )
    }
}

@Composable
private fun KstatNumberFieldMaterial(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier,
        enabled = enabled,
        singleLine = true,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
            keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberSigned
        ),
        shape = MaterialTheme.shapes.large
    )
}

@Composable
fun PathItemCardMaterial(
    path: String,
    icon: ImageVector,
    onDelete: () -> Unit,
    onEdit: (() -> Unit)? = null,
    isLoading: Boolean = false,
    additionalInfo: String? = null
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = path,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    additionalInfo?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                onEdit?.let {
                    IconButton(onClick = it, enabled = !isLoading) {
                        Icon(
                            Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                IconButton(onClick = onDelete, enabled = !isLoading) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
fun KstatConfigItemCardMaterial(
    config: String,
    onDelete: () -> Unit,
    onEdit: (() -> Unit)? = null,
    isLoading: Boolean = false
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    val parts = config.split("|")
                    Text(
                        text = parts.firstOrNull() ?: config,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    if (parts.size > 1) {
                        Text(
                            text = parts.drop(1).joinToString(" "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                onEdit?.let {
                    IconButton(onClick = it, enabled = !isLoading) {
                        Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit), tint = MaterialTheme.colorScheme.primary)
                    }
                }
                IconButton(onClick = onDelete, enabled = !isLoading) {
                    Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete), tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
fun AddKstatPathItemCardMaterial(
    path: String,
    onDelete: () -> Unit,
    onEdit: (() -> Unit)? = null,
    onUpdate: () -> Unit,
    onUpdateFullClone: () -> Unit,
    isLoading: Boolean = false
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Default.Folder,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = path,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                onEdit?.let {
                    IconButton(onClick = it, enabled = !isLoading) {
                        Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit), tint = MaterialTheme.colorScheme.primary)
                    }
                }
                IconButton(onClick = onUpdate, enabled = !isLoading) {
                    Icon(Icons.Default.Update, contentDescription = stringResource(R.string.update), tint = MaterialTheme.colorScheme.secondary)
                }
                IconButton(onClick = onUpdateFullClone, enabled = !isLoading) {
                    Icon(Icons.Default.PlayArrow, contentDescription = stringResource(R.string.susfs_update_full_clone), tint = MaterialTheme.colorScheme.tertiary)
                }
                IconButton(onClick = onDelete, enabled = !isLoading) {
                    Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete), tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
fun AppIconMaterial(
    packageName: String,
    packageInfo: PackageInfo? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val resolvedInfo by produceState(packageInfo, packageName, packageInfo) {
        if (value == null) {
            value = withContext(Dispatchers.IO) {
                AppInfoCache.getAppInfoFromSuperUser(packageName)?.packageInfo
                    ?: runCatching { context.packageManager.getPackageInfo(packageName, 0) }.getOrNull()
            }
        }
    }
    resolvedInfo?.let {
        com.sukisu.nova.ui.component.AppIconImage(
            packageInfo = it,
            label = packageName,
            modifier = modifier,
        )
    }
}

@Composable
fun AppPathGroupCardMaterial(
    packageName: String,
    paths: List<String>,
    onDeleteGroup: () -> Unit,
    onEditGroup: (() -> Unit)? = null,
    isLoading: Boolean
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                AppIconMaterial(
                    packageName = packageName,
                    modifier = Modifier.size(32.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = packageName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Medium
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    onEditGroup?.let {
                        IconButton(onClick = it, enabled = !isLoading) {
                            Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit), tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                    IconButton(onClick = onDeleteGroup, enabled = !isLoading) {
                        Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete), tint = MaterialTheme.colorScheme.error)
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            paths.forEach { path ->
                Text(
                    text = path,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            MaterialTheme.colorScheme.surfaceBright,
                            RoundedCornerShape(6.dp)
                        )
                        .padding(8.dp)
                )
                if (path != paths.last()) {
                    Spacer(modifier = Modifier.height(4.dp))
                }
            }
        }
    }
}
