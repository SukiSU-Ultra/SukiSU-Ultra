package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton

@Composable
internal fun ThemeStoreUploadResultScreen(
    result: ThemeStoreUploadResult,
    onDone: () -> Unit,
) {
    val pending = result.pending && !result.autoApproved
    val container = MaterialTheme.colorScheme.surface
    ExpressiveScaffold(
        containerColor = container,
        topBar = {
            TopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onDone) },
                title = { Text(stringResource(R.string.theme_store_upload_result_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = container,
                    scrolledContainerColor = container,
                ),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(
                start = 18.dp,
                end = 18.dp,
                top = 10.dp,
                bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 24.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                    ),
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = if (pending) Icons.Rounded.Schedule
                                else Icons.Rounded.CheckCircle,
                                contentDescription = null,
                                tint = if (pending) MaterialTheme.colorScheme.tertiary
                                else MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(30.dp),
                            )
                            Spacer(Modifier.size(10.dp))
                            Text(
                                text = stringResource(
                                    if (pending) R.string.theme_store_upload_result_pending
                                    else R.string.theme_store_upload_result_published,
                                ),
                                style = MaterialTheme.typography.titleLarge,
                            )
                        }
                        Text(
                            text = result.message,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        HorizontalDivider()
                        ResultInfoRow(
                            stringResource(R.string.theme_store_upload_result_theme_id),
                            result.themeId.ifBlank { "—" },
                        )
                        if (result.submissionId.isNotBlank()) {
                            ResultInfoRow(
                                stringResource(R.string.theme_store_upload_result_submission_id),
                                result.submissionId,
                            )
                        }
                        ResultInfoRow(
                            label = stringResource(R.string.theme_store_sha256),
                            value = result.sha256.ifBlank { "—" },
                            monospace = true,
                        )
                    }
                }
            }
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                    ),
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.theme_store_upload_result_flow),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        FlowStep(
                            stringResource(R.string.theme_store_upload_result_step_local),
                            done = true,
                        )
                        FlowStep(
                            stringResource(R.string.theme_store_upload_result_step_upload),
                            done = true,
                        )
                        FlowStep(
                            stringResource(R.string.theme_store_upload_result_step_verify),
                            done = true,
                        )
                        if (pending) {
                            FlowStep(
                                stringResource(R.string.theme_store_upload_result_step_review),
                                done = false,
                            )
                            FlowStep(
                                stringResource(R.string.theme_store_upload_result_step_publish),
                                done = false,
                            )
                        } else {
                            FlowStep(
                                stringResource(R.string.theme_store_upload_result_step_auto),
                                done = true,
                            )
                        }
                    }
                }
            }
            item {
                Button(
                    onClick = onDone,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    shape = RoundedCornerShape(50),
                ) {
                    Text(stringResource(R.string.theme_store_upload_result_done))
                }
            }
        }
    }
}

@Composable
private fun ResultInfoRow(label: String, value: String, monospace: Boolean = false) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SelectionContainer {
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            )
        }
    }
}

@Composable
private fun FlowStep(label: String, done: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            imageVector = if (done) Icons.Rounded.CheckCircle else Icons.Rounded.Schedule,
            contentDescription = null,
            tint = if (done) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.size(8.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = if (done) MaterialTheme.colorScheme.onSurface
            else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
