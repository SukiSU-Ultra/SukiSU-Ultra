package com.sukisu.ultra.ai

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.ai.R

@Composable
fun AiMarkdownMaterial(
    content: String,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    val linkColor = MaterialTheme.colorScheme.primary
    val codeBackground = MaterialTheme.colorScheme.surfaceContainerLowest
    val blocks = remember(content, linkColor, codeBackground) {
        parseAiMarkdown(content, linkColor, codeBackground)
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        blocks.forEach { block ->
            AiMarkdownBlockMaterial(block, allowCodeExecution, onRunCode)
        }
    }
}

@Composable
private fun AiMarkdownBlockMaterial(
    block: AiMarkdownBlock,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    when (block) {
        is AiMarkdownBlock.Paragraph -> Text(
            text = block.text,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )

        is AiMarkdownBlock.Heading -> Text(
            text = block.text,
            style = when (block.level) {
                1 -> MaterialTheme.typography.titleLarge
                2 -> MaterialTheme.typography.titleMedium
                else -> MaterialTheme.typography.titleSmall
            },
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface,
        )

        is AiMarkdownBlock.Code -> AiCodeBlockMaterial(
            block = block,
            allowCodeExecution = allowCodeExecution,
            onRunCode = onRunCode,
        )

        is AiMarkdownBlock.ListBlock -> AiListBlockMaterial(
            block = block,
            allowCodeExecution = allowCodeExecution,
            onRunCode = onRunCode,
        )

        is AiMarkdownBlock.Quote -> {
            val quoteColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.4f)
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .drawBehind {
                        drawRect(
                            color = quoteColor,
                            topLeft = Offset.Zero,
                            size = Size(3.dp.toPx(), size.height),
                        )
                    }
                    .padding(start = 12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                block.blocks.forEach { child ->
                    AiMarkdownBlockMaterial(child, allowCodeExecution, onRunCode)
                }
            }
        }

        is AiMarkdownBlock.Table -> AiTableMaterial(block)

        AiMarkdownBlock.Divider -> HorizontalDivider(
            color = MaterialTheme.colorScheme.outlineVariant,
        )
    }
}

@Composable
private fun AiListBlockMaterial(
    block: AiMarkdownBlock.ListBlock,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        block.items.forEachIndexed { index, item ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
            ) {
                Text(
                    text = if (block.ordered) "${block.start + index}." else "•",
                    modifier = Modifier
                        .widthIn(min = 22.dp)
                        .padding(top = 1.dp),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    item.blocks.forEach { child ->
                        AiMarkdownBlockMaterial(child, allowCodeExecution, onRunCode)
                    }
                }
            }
        }
    }
}

@Composable
private fun AiTableMaterial(block: AiMarkdownBlock.Table) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerLowest),
    ) {
        if (block.header.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.08f)),
            ) {
                block.header.forEach { cell ->
                    AiTableCellMaterial(
                        text = cell,
                        header = true,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
        block.rows.forEach { row ->
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
            Row(modifier = Modifier.fillMaxWidth()) {
                row.forEach { cell ->
                    AiTableCellMaterial(
                        text = cell,
                        header = false,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
private fun AiTableCellMaterial(
    text: androidx.compose.ui.text.AnnotatedString,
    header: Boolean,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        modifier = modifier.padding(horizontal = 10.dp, vertical = 8.dp),
        style = if (header) {
            MaterialTheme.typography.labelLarge
        } else {
            MaterialTheme.typography.bodySmall
        },
        fontWeight = if (header) FontWeight.Bold else FontWeight.Normal,
        color = MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
private fun AiCodeBlockMaterial(
    block: AiMarkdownBlock.Code,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    val copy = rememberAiCopyText()
    val label = block.language.ifBlank { "text" }
    val canRun = block.executable && allowCodeExecution
    val horizontal = rememberScrollState()
    val vertical = rememberScrollState()

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLowest,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                    .padding(start = 12.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = label,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.labelMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (block.executable) {
                    CodeBadgeMaterial(
                        text = stringResource(
                            if (allowCodeExecution) {
                                R.string.ai_code_executable
                            } else {
                                R.string.ai_code_execution_off
                            }
                        ),
                        active = allowCodeExecution,
                    )
                }
                if (canRun) {
                    IconButton(
                        onClick = { onRunCode(block.code) },
                        modifier = Modifier.size(32.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.PlayArrow,
                            contentDescription = stringResource(R.string.ai_code_run),
                            modifier = Modifier.size(18.dp),
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
                IconButton(
                    onClick = { copy(block.code) },
                    modifier = Modifier.size(32.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ContentCopy,
                        contentDescription = stringResource(R.string.ai_code_copy),
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            SelectionContainer {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 360.dp)
                        .horizontalScroll(horizontal)
                        .verticalScroll(vertical),
                ) {
                    Text(
                        text = block.code,
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        }
    }
}

@Composable
private fun CodeBadgeMaterial(text: String, active: Boolean) {
    Surface(
        shape = RoundedCornerShape(5.dp),
        color = if (active) {
            MaterialTheme.colorScheme.primaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceContainerHighest
        },
        contentColor = if (active) {
            MaterialTheme.colorScheme.onPrimaryContainer
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
        )
    }
}
