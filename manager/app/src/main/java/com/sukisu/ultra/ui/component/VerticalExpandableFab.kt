package com.sukisu.ultra.ui.component

import androidx.compose.animation.*
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R

// 菜单项数据类
data class FabMenuItem(
    val icon: ImageVector,
    val labelRes: Int,
    val color: Color = Color.Unspecified,
    val onClick: () -> Unit
)

// 动画配置
object FabAnimationConfig {
    const val ANIMATION_DURATION = 300
    const val STAGGER_DELAY = 50
    val BUTTON_SPACING = 72.dp
    val BUTTON_SIZE = 56.dp
    val SMALL_BUTTON_SIZE = 48.dp
}

@Composable
fun VerticalExpandableFab(
    menuItems: List<FabMenuItem>,
    modifier: Modifier = Modifier,
    buttonSize: Dp = FabAnimationConfig.BUTTON_SIZE,
    smallButtonSize: Dp = FabAnimationConfig.SMALL_BUTTON_SIZE,
    buttonSpacing: Dp = FabAnimationConfig.BUTTON_SPACING,
    animationDurationMs: Int = FabAnimationConfig.ANIMATION_DURATION,
    staggerDelayMs: Int = FabAnimationConfig.STAGGER_DELAY,
    mainButtonIcon: ImageVector = Icons.Filled.Add,
    mainButtonExpandedIcon: ImageVector = Icons.Filled.Close,
    onMainButtonClick: (() -> Unit)? = null,
) {
    var isExpanded by remember { mutableStateOf(false) }

    // 主按钮旋转动画
    val rotationAngle by animateFloatAsState(
        targetValue = if (isExpanded) 45f else 0f,
        animationSpec = tween(
            durationMillis = animationDurationMs,
            easing = FastOutSlowInEasing
        ),
        label = "mainButtonRotation"
    )

    // 主按钮缩放动画
    val mainButtonScale by animateFloatAsState(
        targetValue = if (isExpanded) 1.1f else 1f,
        animationSpec = tween(
            durationMillis = animationDurationMs,
            easing = FastOutSlowInEasing
        ),
        label = "mainButtonScale"
    )

    Box(
        modifier = modifier.wrapContentSize(),
        contentAlignment = Alignment.BottomEnd
    ) {
        // 子菜单按钮
        menuItems.forEachIndexed { index, menuItem ->
            val animatedOffsetY by animateFloatAsState(
                targetValue = if (isExpanded) {
                    -(buttonSpacing.value * (index + 1))
                } else {
                    0f
                },
                animationSpec = tween(
                    durationMillis = animationDurationMs,
                    delayMillis = if (isExpanded) {
                        index * staggerDelayMs
                    } else {
                        (menuItems.size - index - 1) * staggerDelayMs
                    },
                    easing = FastOutSlowInEasing
                ),
                label = "fabOffset$index"
            )

            val animatedScale by animateFloatAsState(
                targetValue = if (isExpanded) 1f else 0f,
                animationSpec = tween(
                    durationMillis = animationDurationMs,
                    delayMillis = if (isExpanded) {
                        index * staggerDelayMs + 100
                    } else {
                        (menuItems.size - index - 1) * staggerDelayMs
                    },
                    easing = FastOutSlowInEasing
                ),
                label = "fabScale$index"
            )

            val animatedAlpha by animateFloatAsState(
                targetValue = if (isExpanded) 1f else 0f,
                animationSpec = tween(
                    durationMillis = animationDurationMs,
                    delayMillis = if (isExpanded) {
                        index * staggerDelayMs + 150
                    } else {
                        (menuItems.size - index - 1) * staggerDelayMs
                    },
                    easing = FastOutSlowInEasing
                ),
                label = "fabAlpha$index"
            )

            // 子按钮容器（包含标签）
            Row(
                modifier = Modifier
                    .offset(y = animatedOffsetY.dp)
                    .scale(animatedScale)
                    .alpha(animatedAlpha),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.End
            ) {
                // 标签
                AnimatedVisibility(
                    visible = isExpanded && animatedScale > 0.5f,
                    enter = slideInHorizontally(
                        initialOffsetX = { it / 2 },
                        animationSpec = tween(200)
                    ) + fadeIn(animationSpec = tween(200)),
                    exit = slideOutHorizontally(
                        targetOffsetX = { it / 2 },
                        animationSpec = tween(150)
                    ) + fadeOut(animationSpec = tween(150))
                ) {
                    Surface(
                        modifier = Modifier.padding(end = 16.dp),
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.inverseSurface,
                        tonalElevation = 6.dp
                    ) {
                        Text(
                            text = stringResource(menuItem.labelRes),
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.inverseOnSurface
                        )
                    }
                }

                // 子按钮
                SmallFloatingActionButton(
                    onClick = {
                        menuItem.onClick()
                        isExpanded = false
                    },
                    modifier = Modifier.size(smallButtonSize),
                    containerColor = if (menuItem.color != Color.Unspecified) {
                        menuItem.color
                    } else {
                        MaterialTheme.colorScheme.secondary
                    },
                    contentColor = if (menuItem.color != Color.Unspecified) {
                        if (menuItem.color == Color.Gray) Color.White
                        else MaterialTheme.colorScheme.onSecondary
                    } else {
                        MaterialTheme.colorScheme.onSecondary
                    },
                    elevation = FloatingActionButtonDefaults.elevation(
                        defaultElevation = 4.dp,
                        pressedElevation = 6.dp
                    )
                ) {
                    Icon(
                        imageVector = menuItem.icon,
                        contentDescription = stringResource(menuItem.labelRes),
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }

        // 主按钮
        FloatingActionButton(
            onClick = {
                onMainButtonClick?.invoke()
                isExpanded = !isExpanded
            },
            modifier = Modifier
                .size(buttonSize)
                .scale(mainButtonScale),
            elevation = FloatingActionButtonDefaults.elevation(
                defaultElevation = 6.dp,
                pressedElevation = 8.dp,
                hoveredElevation = 8.dp
            )
        ) {
            Icon(
                imageVector = if (isExpanded) mainButtonExpandedIcon else mainButtonIcon,
                contentDescription = stringResource(
                    if (isExpanded) R.string.collapse_menu else R.string.expand_menu
                ),
                modifier = Modifier
                    .size(24.dp)
                    .rotate(if (mainButtonIcon == Icons.Filled.Add) rotationAngle else 0f)
            )
        }
    }
}

// 预设菜单项
object FabMenuPresets {
    fun getScrollMenuItems(
        onScrollToTop: () -> Unit,
        onScrollToBottom: () -> Unit
    ) = listOf(
        FabMenuItem(
            icon = Icons.Filled.KeyboardArrowDown,
            labelRes = R.string.scroll_to_bottom,
            onClick = onScrollToBottom
        ),
        FabMenuItem(
            icon = Icons.Filled.KeyboardArrowUp,
            labelRes = R.string.scroll_to_top,
            onClick = onScrollToTop
        )
    )

    @Composable
    fun getBatchActionMenuItems(
        onCancel: () -> Unit,
        onDeny: () -> Unit,
        onAllow: () -> Unit,
        onUnmountModules: () -> Unit,
        onDisableUnmount: () -> Unit
    ) = listOf(
        FabMenuItem(
            icon = Icons.Filled.Close,
            labelRes = R.string.cancel,
            color = Color.Gray,
            onClick = onCancel
        ),
        FabMenuItem(
            icon = Icons.Filled.Block,
            labelRes = R.string.deny_authorization,
            color = MaterialTheme.colorScheme.error,
            onClick = onDeny
        ),
        FabMenuItem(
            icon = Icons.Filled.Check,
            labelRes = R.string.grant_authorization,
            color = MaterialTheme.colorScheme.primary,
            onClick = onAllow
        ),
        FabMenuItem(
            icon = Icons.Filled.FolderOff,
            labelRes = R.string.unmount_modules,
            onClick = onUnmountModules
        ),
        FabMenuItem(
            icon = Icons.Filled.Folder,
            labelRes = R.string.disable_unmount,
            onClick = onDisableUnmount
        )
    )
}