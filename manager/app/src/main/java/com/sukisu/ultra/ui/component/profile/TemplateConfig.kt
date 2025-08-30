package com.sukisu.ultra.ui.component.profile

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ReadMore
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.ArrowDropUp
import androidx.compose.material.icons.filled.Create
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.listAppProfileTemplates
import com.sukisu.ultra.ui.util.setSepolicy
import com.sukisu.ultra.ui.viewmodel.getTemplateInfoById

/**
 * @author weishu
 * @date 2023/10/21.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TemplateConfig(
    profile: Natives.Profile,
    onViewTemplate: (id: String) -> Unit = {},
    onManageTemplate: () -> Unit = {},
    onProfileChange: (Natives.Profile) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    var template by rememberSaveable {
        mutableStateOf(profile.rootTemplate ?: "")
    }
    val profileTemplates = listAppProfileTemplates()
    val noTemplates = profileTemplates.isEmpty()

    ListItem(headlineContent = {
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
        ) {
            OutlinedTextField(
                modifier = Modifier
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                    .fillMaxWidth(),
                readOnly = true,
                label = { Text(stringResource(R.string.profile_template)) },
                value = template.ifEmpty { "None" },
                onValueChange = {},
                trailingIcon = {
                    if (noTemplates) {
                        IconButton(
                            onClick = onManageTemplate
                        ) {
                            Icon(Icons.Filled.Create, null)
                        }
                    } else if (expanded) Icon(Icons.Filled.ArrowDropUp, null)
                    else Icon(Icons.Filled.ArrowDropDown, null)
                },
            )
            if (profileTemplates.isEmpty()) {
                return@ExposedDropdownMenuBox
            }
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                profileTemplates.forEach { tid ->
                    val templateInfo =
                        getTemplateInfoById(tid) ?: return@forEach
                    DropdownMenuItem(
                        text = { Text(tid) },
                        onClick = {
                            template = tid
                            if (setSepolicy(tid, templateInfo.rules.joinToString("\n"))) {
                                onProfileChange(
                                    profile.copy(
                                        rootTemplate = tid,
                                        rootUseDefault = false,
                                        uid = templateInfo.uid,
                                        gid = templateInfo.gid,
                                        groups = templateInfo.groups,
                                        capabilities = templateInfo.capabilities,
                                        context = templateInfo.context,
                                        namespace = templateInfo.namespace,
                                    )
                                )
                            }
                            expanded = false
                        },
                        trailingIcon = {
                            IconButton(onClick = {
                                onViewTemplate(tid)
                            }) {
                                Icon(Icons.AutoMirrored.Filled.ReadMore, null)
                            }
                        }
                    )
                }
            }
        }
    })
}