package com.sukisu.ultra.ui.screen.susfs

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedDropdownItem
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@Composable
internal fun SuSFSMaterial(
    state: SuSFSUiState,
    onSelectTab: (SuSFSTab) -> Unit,
    onBack: () -> Unit,
    content: @Composable () -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(customText(CustomTextKey.EXTENSION_SUSFS)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                scrollBehavior = scrollBehavior,
                colors = expressiveTopAppBarColors(),
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).nestedScroll(scrollBehavior.nestedScrollConnection)) {
            SegmentedColumn(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                content = listOf({
                    SegmentedDropdownItem(
                        title = stringResource(R.string.susfs_config_title),
                        items = SuSFSTab.entries.map { stringResource(it.displayNameRes) },
                        selectedIndex = state.selectedTab.ordinal,
                        onItemSelected = { onSelectTab(SuSFSTab.entries[it]) },
                    )
                }),
            )
            Box(Modifier.fillMaxWidth().height(4.dp)) {
                if (state.isLoading || state.isLoadingFeatures && state.selectedTab == SuSFSTab.ENABLED_FEATURES) {
                    LinearWavyProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
            }
            key(state.selectedTab) {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    state.error?.let {
                        Surface(color = MaterialTheme.colorScheme.errorContainer, shape = MaterialTheme.shapes.large) {
                            Text(it.localizedMessage ?: stringResource(R.string.operation_failed), Modifier.fillMaxWidth().padding(16.dp))
                        }
                    }
                    content()
                    Spacer(Modifier.height(16.dp))
                }
            }
        }
    }
}
