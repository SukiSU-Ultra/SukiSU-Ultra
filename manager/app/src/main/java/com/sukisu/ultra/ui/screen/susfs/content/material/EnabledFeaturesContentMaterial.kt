package com.sukisu.ultra.ui.screen.susfs.content.material

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.component.material.EmptyStateCardMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.FeatureStatusCardMaterial
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature

@Composable
fun EnabledFeaturesContentMaterial(
    enabledFeatures: List<EnabledFeature>,
    onRefresh: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Settings,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    text = stringResource(R.string.susfs_enabled_features_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (enabledFeatures.isEmpty()) {
            EmptyStateCardMaterial(message = stringResource(R.string.susfs_no_features_found))
        } else {
            enabledFeatures.forEach { feature ->
                FeatureStatusCardMaterial(
                    feature = feature,
                    onRefresh = onRefresh
                )
            }
        }
    }

    Button(
        onClick = onRefresh,
        modifier = Modifier.padding(top = 12.dp).fillMaxWidth()
    ) {
        Icon(Icons.Default.Refresh, contentDescription = null)
        Spacer(Modifier.width(4.dp))
        Text(stringResource(R.string.refresh))
    }
}
