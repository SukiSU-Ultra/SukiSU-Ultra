package com.sukisu.ultra.ui.screen.ai

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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.icon.extended.Play
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun AiMarkdownMiuix(
    content: String,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    val linkColor = colorScheme.primary
    val codeBackground = colorScheme.surfaceContainerHighest
    val blocks = remember(content, linkColor, codeBackground) {
        parseAiMarkdown(content, linkColor, codeBackground)
    }
    Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
        blocks.forEach { block ->
            AiMarkdownBlockMiuix(block, allowCodeExecution, onRunCode)
        }
    }
}

@Composable
private fun AiMarkdownBlockMiuix(
    block: AiMarkdownBlock,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    when (block) {
        is AiMarkdownBlock.Paragraph -> Text(
            text = block.text,
            style = MiuixTheme.textStyles.body1,
            color = colorScheme.onSurface,
        )

        is AiMarkdownBlock.Heading -> Text(
            text = block.text,
            style = when (block.level) {
                1 -> MiuixTheme.textStyles.title3
                2 -> MiuixTheme.textStyles.title4
                else -> MiuixTheme.textStyles.body1
            },
            fontWeight = FontWeight.Bold,
            color = colorScheme.onSurface,
        )

        is AiMarkdownBlock.Code -> AiCodeBlockMiuix(
            block = block,
            allowCodeExecution = allowCodeExecution,
            onRunCode = onRunCode,
        )

        is AiMarkdownBlock.ListBlock -> AiListBlockMiuix(
            block = block,
            allowCodeExecution = allowCodeExecution,
            onRunCode = onRunCode,
        )

        is AiMarkdownBlock.Quote -> {
            val quoteColor = colorScheme.primary.copy(alpha = 0.4f)
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
                    .padding(start = 11.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                block.blocks.forEach { child ->
                    AiMarkdownBlockMiuix(child, allowCodeExecution, onRunCode)
                }
            }
        }

        is AiMarkdownBlock.Table -> AiTableMiuix(block)

        AiMarkdownBlock.Divider -> HorizontalDivider()
    }
}

@Composable
private fun AiListBlockMiuix(
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
                        .widthIn(min = 21.dp)
                        .padding(top = 1.dp),
                    style = MiuixTheme.textStyles.body1,
                    color = colorScheme.onSurfaceVariantSummary,
                )
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(5.dp),
                ) {
                    item.blocks.forEach { child ->
                        AiMarkdownBlockMiuix(child, allowCodeExecution, onRunCode)
                    }
                }
            }
        }
    }
}

@Composable
private fun AiTableMiuix(block: AiMarkdownBlock.Table) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(colorScheme.surfaceContainerHighest),
    ) {
        if (block.header.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(colorScheme.primary.copy(alpha = 0.10f)),
            ) {
                block.header.forEach { cell ->
                    AiTableCellMiuix(
                        text = cell,
                        header = true,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
        block.rows.forEach { row ->
            HorizontalDivider()
            Row(modifier = Modifier.fillMaxWidth()) {
                row.forEach { cell ->
                    AiTableCellMiuix(
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
private fun AiTableCellMiuix(
    text: AnnotatedString,
    header: Boolean,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        modifier = modifier.padding(horizontal = 10.dp, vertical = 8.dp),
        style = if (header) MiuixTheme.textStyles.footnote1 else MiuixTheme.textStyles.body2,
        fontWeight = if (header) FontWeight.Bold else FontWeight.Normal,
        color = colorScheme.onSurface,
    )
}

@Composable
private fun AiCodeBlockMiuix(
    block: AiMarkdownBlock.Code,
    allowCodeExecution: Boolean,
    onRunCode: (String) -> Unit,
) {
    val copy = rememberAiCopyText()
    val label = block.language.ifBlank { "text" }
    val canRun = block.executable && allowCodeExecution
    val horizontal = rememberScrollState()
    val vertical = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(colorScheme.surfaceContainerHighest, RoundedCornerShape(10.dp)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colorScheme.surfaceContainerHigh)
                .padding(start = 10.dp, end = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = label,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                style = MiuixTheme.textStyles.footnote1,
                fontFamily = FontFamily.Monospace,
                color = colorScheme.onSurfaceVariantSummary,
            )
            if (block.executable) {
                CodeBadgeMiuix(
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
                        imageVector = MiuixIcons.Play,
                        contentDescription = stringResource(R.string.ai_code_run),
                        modifier = Modifier.size(16.dp),
                        tint = colorScheme.primary,
                    )
                }
            }
            IconButton(
                onClick = { copy(block.code) },
                modifier = Modifier.size(32.dp),
            ) {
                Icon(
                    imageVector = MiuixIcons.Copy,
                    contentDescription = stringResource(R.string.ai_code_copy),
                    modifier = Modifier.size(15.dp),
                    tint = colorScheme.onSurfaceVariantSummary,
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
                    modifier = Modifier.padding(11.dp),
                    style = MiuixTheme.textStyles.body2,
                    fontFamily = FontFamily.Monospace,
                    color = colorScheme.onSurface,
                )
            }
        }
    }
}

@Composable
private fun CodeBadgeMiuix(text: String, active: Boolean) {
    Text(
        text = text,
        modifier = Modifier
            .background(
                if (active) colorScheme.primaryContainer else colorScheme.surfaceContainerHighest,
                RoundedCornerShape(5.dp),
            )
            .padding(horizontal = 6.dp, vertical = 2.dp),
        style = MiuixTheme.textStyles.footnote1,
        color = if (active) colorScheme.onPrimaryContainer else colorScheme.onSurfaceVariantSummary,
    )
}
