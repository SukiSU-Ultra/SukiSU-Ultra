package com.sukisu.ultra.ui.screen.sukisufs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R

/**
 * Miuix variant of the sukisu-fs screen. Reuses the Material 3
 * building blocks; a richer Miuix implementation can be added
 * later by replacing the Scaffold with `MiuixScaffold`.
 */
@Composable
internal fun SukisuFsMiuix(
    mountStatus: SukisuFsMountState?,
    rules: List<SukisuFsRule>,
    busy: Boolean,
    error: String?,
    actions: SukisuFsActions,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sukisufs_title)) },
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            if (busy) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item("status") {
                    Text(
                        text = if (mountStatus?.mounted == true) {
                            "${mountStatus.source} -> ${mountStatus.target}"
                        } else {
                            stringResource(R.string.sukisufs_not_mounted)
                        },
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
                error?.takeIf { it.isNotEmpty() }?.let {
                    item("error") {
                        Text(text = it, color = MaterialTheme.colorScheme.error)
                    }
                }
                items(rules, key = { it.path + "_" + it.view.name }) { rule ->
                    Text(
                        text = "${rule.view.name} uid[${rule.uidMin}..${rule.uidMax}] ${rule.path}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}
