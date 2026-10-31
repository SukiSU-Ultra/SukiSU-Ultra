package com.sukisu.ultra.ui.screen.ai

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.HelpOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Close
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun AiQuestionPanelMiuix(
    question: AiUserQuestion,
    onAnswer: (String?) -> Unit,
) {
    var custom by remember(question.question, question.options) { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                colorScheme.surfaceContainerHigh,
                RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
            )
            .heightIn(max = 360.dp)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.AutoMirrored.Rounded.HelpOutline,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
                tint = colorScheme.primary,
            )
            Text(
                text = stringResource(R.string.ai_question_title),
                modifier = Modifier.padding(start = 8.dp).weight(1f),
                style = MiuixTheme.textStyles.title4,
                color = colorScheme.primary,
            )
            IconButton(
                onClick = { onAnswer(null) },
                modifier = Modifier.size(28.dp),
            ) {
                Icon(
                    imageVector = MiuixIcons.Close,
                    contentDescription = stringResource(R.string.ai_question_dismiss),
                    modifier = Modifier.size(16.dp),
                    tint = colorScheme.onSurfaceVariantSummary,
                )
            }
        }
        Text(
            text = question.question,
            style = MiuixTheme.textStyles.body1,
            color = colorScheme.onSurface,
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            question.options.forEach { option ->
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(16.dp))
                        .background(colorScheme.surfaceContainerHighest)
                        .clickable { onAnswer(option) }
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = option,
                        style = MiuixTheme.textStyles.body1,
                        color = colorScheme.onSurface,
                    )
                }
            }
        }
        if (question.allowCustom) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextField(
                    value = custom,
                    onValueChange = { custom = it },
                    modifier = Modifier.weight(1f),
                    label = stringResource(R.string.ai_question_custom_hint),
                    useLabelAsPlaceholder = true,
                    maxLines = 3,
                )
                Spacer(Modifier.width(8.dp))
                TextButton(
                    text = stringResource(R.string.ai_question_send),
                    onClick = {
                        val answer = custom.trim()
                        if (answer.isNotEmpty()) onAnswer(answer)
                    },
                    enabled = custom.isNotBlank(),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }
}
