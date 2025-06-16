package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.material3.ExperimentalMaterial3Api
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import com.sukisu.ultra.ui.util.SuSFSManager
import kotlinx.coroutines.launch

/**
 * 模块功能内容组件
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ModuleFeaturesContent(
    susSuMode: Int,
    onSusSuModeChange: (Int) -> Unit,
    susSuModeExpanded: Boolean,
    onSusSuModeExpandedChange: (Boolean) -> Unit,
    hideLoops: Boolean,
    onHideLoopsChange: (Boolean) -> Unit,
    hideVendorSepolicy: Boolean,
    onHideVendorSepolicyChange: (Boolean) -> Unit,
    hideCompatMatrix: Boolean,
    onHideCompatMatrixChange: (Boolean) -> Unit,
    fakeServiceList: Boolean,
    onFakeServiceListChange: (Boolean) -> Unit,
    spoofUname: Int,
    onSpoofUnameChange: (Int) -> Unit,
    spoofUnameExpanded: Boolean,
    onSpoofUnameExpandedChange: (Boolean) -> Unit,
    kernelVersion: String,
    kernelBuild: String,
    onShowSetKernelVersionDialog: () -> Unit,
    spoofCmdline: Boolean,
    onSpoofCmdlineChange: (Boolean) -> Unit,
    hideCusRom: Boolean,
    onHideCusRomChange: (Boolean) -> Unit,
    hideGapps: Boolean,
    onHideGappsChange: (Boolean) -> Unit,
    hideRevanced: Boolean,
    onHideRevancedChange: (Boolean) -> Unit,
    forceHideLsposed: Boolean,
    onForceHideLsposedChange: (Boolean) -> Unit,
    isLoading: Boolean
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // 核心功能设置卡片
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
            elevation = getCardElevation()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = stringResource(R.string.susfs_module_features_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                // sus_su模式
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_sussu_mode_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_sussu_mode_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Box {
                        ExposedDropdownMenuBox(
                            expanded = susSuModeExpanded,
                            onExpandedChange = { onSusSuModeExpandedChange(!susSuModeExpanded) }
                        ) {
                            OutlinedTextField(
                                modifier = Modifier
                                    .width(120.dp)
                                    .menuAnchor(MenuAnchorType.PrimaryEditable, true),
                                readOnly = true,
                                value = when (susSuMode) {
                                    -1 -> stringResource(R.string.suki_disabled)
                                    0 -> stringResource(R.string.susfs_sussu_mode_0)
                                    1 -> stringResource(R.string.susfs_sussu_mode_1)
                                    2 -> stringResource(R.string.susfs_sussu_mode_2)
                                    else -> susSuMode.toString()
                                },
                                onValueChange = { },
                                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = susSuModeExpanded) },
                                shape = RoundedCornerShape(8.dp)
                            )
                            
                            ExposedDropdownMenu(
                                expanded = susSuModeExpanded,
                                onDismissRequest = { onSusSuModeExpandedChange(false) }
                            ) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.susfs_sussu_mode_0)) },
                                    onClick = {
                                        onSusSuModeChange(0)
                                        onSusSuModeExpandedChange(false)
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.susfs_sussu_mode_1)) },
                                    onClick = {
                                        onSusSuModeChange(1)
                                        onSusSuModeExpandedChange(false)
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.susfs_sussu_mode_2)) },
                                    onClick = {
                                        onSusSuModeChange(2)
                                        onSusSuModeExpandedChange(false)
                                    }
                                )
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                // 隐藏Loop设备
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_hide_loops_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_hide_loops_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = hideLoops,
                        onCheckedChange = { onHideLoopsChange(it) },
                        enabled = !isLoading
                    )
                }
                
                // 隐藏Vendor SEPolicy
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_hide_vendor_sepolicy_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_hide_vendor_sepolicy_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = hideVendorSepolicy,
                        onCheckedChange = { onHideVendorSepolicyChange(it) },
                        enabled = !isLoading
                    )
                }
                
                // 隐藏兼容性矩阵
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_hide_compat_matrix_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_hide_compat_matrix_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = hideCompatMatrix,
                        onCheckedChange = { onHideCompatMatrixChange(it) },
                        enabled = !isLoading
                    )
                }
                
                // 伪造服务列表
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_fake_service_list_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_fake_service_list_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = fakeServiceList,
                        onCheckedChange = { onFakeServiceListChange(it) },
                        enabled = !isLoading
                    )
                }
            }
        }
        
        // 伪装和防检测功能卡片
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
            elevation = getCardElevation()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = stringResource(R.string.susfs_anti_detect_features_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                // 伪装Uname
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_spoof_uname_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_spoof_uname_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Box {
                        ExposedDropdownMenuBox(
                            expanded = spoofUnameExpanded,
                            onExpandedChange = { onSpoofUnameExpandedChange(!spoofUnameExpanded) }
                        ) {
                            OutlinedTextField(
                                modifier = Modifier
                                    .width(120.dp)
                                    .menuAnchor(MenuAnchorType.PrimaryEditable, true),
                                readOnly = true,
                                value = when (spoofUname) {
                                    0 -> stringResource(R.string.suki_disabled)
                                    1 -> stringResource(R.string.susfs_spoof_uname_mode_1)
                                    2 -> stringResource(R.string.susfs_spoof_uname_mode_2)
                                    else -> spoofUname.toString()
                                },
                                onValueChange = { },
                                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = spoofUnameExpanded) },
                                shape = RoundedCornerShape(8.dp)
                            )
                            
                            ExposedDropdownMenu(
                                expanded = spoofUnameExpanded,
                                onDismissRequest = { onSpoofUnameExpandedChange(false) }
                            ) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.suki_disabled)) },
                                    onClick = {
                                        onSpoofUnameChange(0)
                                        onSpoofUnameExpandedChange(false)
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.susfs_spoof_uname_mode_1)) },
                                    onClick = {
                                        onSpoofUnameChange(1)
                                        onSpoofUnameExpandedChange(false)
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.susfs_spoof_uname_mode_2)) },
                                    onClick = {
                                        onSpoofUnameChange(2)
                                        onSpoofUnameExpandedChange(false)
                                    }
                                )
                            }
                        }
                    }
                }
                
                // 显示当前内核信息并允许设置
                if (spoofUname > 0) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 16.dp, end = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_current_kernel_info),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_kernel_version, kernelVersion),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            text = stringResource(R.string.susfs_kernel_build, kernelBuild),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Button(
                            onClick = onShowSetKernelVersionDialog,
                            modifier = Modifier.align(Alignment.End),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text(stringResource(R.string.susfs_set_kernel_info))
                        }
                    }
                }
                
                // 伪装命令行
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_spoof_cmdline_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_spoof_cmdline_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = spoofCmdline,
                        onCheckedChange = { onSpoofCmdlineChange(it) },
                        enabled = !isLoading
                    )
                }
                
                // 隐藏自定义ROM信息
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_hide_cusrom_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_hide_cusrom_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = hideCusRom,
                        onCheckedChange = { onHideCusRomChange(it) },
                        enabled = !isLoading
                    )
                }
            }
        }
        
        // 应用隐藏卡片
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
            elevation = getCardElevation()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = stringResource(R.string.susfs_app_hiding_features_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                // 隐藏GApps情况
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_hide_gapps_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_hide_gapps_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = hideGapps,
                        onCheckedChange = { onHideGappsChange(it) },
                        enabled = !isLoading
                    )
                }
                
                // 隐藏ReVanced情况
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_hide_revanced_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_hide_revanced_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = hideRevanced,
                        onCheckedChange = { onHideRevancedChange(it) },
                        enabled = !isLoading
                    )
                }
                
                // 强制隐藏LSPosed
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_force_hide_lsposed_title),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.susfs_force_hide_lsposed_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Switch(
                        checked = forceHideLsposed,
                        onCheckedChange = { onForceHideLsposedChange(it) },
                        enabled = !isLoading
                    )
                }
            }
        }
    }
} 